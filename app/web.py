"""FastAPI web UI: domains, host records, Aliyun credentials, certificates and settings."""

from __future__ import annotations

import contextlib
import datetime
import io
import logging
import sqlite3
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from . import alidns, auth as auth_module, certstore, crypto
from . import db, names, notify, repo
from . import config as config_module
from .auth import Auth
from .scheduler import Scheduler
from .service import Service

logger = logging.getLogger(__name__)

SECRET_SETTINGS = ("smtp_password", "pfx_password")
NUMERIC_LIMITS = {
    "renew_before_days": (1, 365),
    "warn_before_days": (1, 365),
    "dns_propagation_timeout": (30, 1800),
    "renewal_hour": (0, 23),
}
EDITABLE_SETTINGS = (
    "ca_name", "ca_directory", "contact_email", "renew_before_days", "warn_before_days",
    "dns_propagation_timeout", "cert_key_type", "pfx_password", "smtp_host", "smtp_port",
    "smtp_username", "smtp_password", "smtp_from", "smtp_use_ssl", "notify_enabled",
    "notify_to", "renewal_hour", "auto_renew_enabled",
)
SWITCH_SETTINGS = ("smtp_use_ssl", "notify_enabled", "auto_renew_enabled")


def create_app(settings: config_module.Settings) -> FastAPI:
    db.init(settings.db_path)
    auth = Auth(settings)
    service = Service(settings)
    scheduler = Scheduler(service)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        scheduler.start()
        interrupted = service.recover_interrupted_jobs()
        if interrupted:
            logger.warning("发现 %d 个被中断的签发任务，已标记为失败", interrupted)
        try:
            yield
        finally:
            scheduler.stop()
            service.executor.shutdown(wait=False)

    app = FastAPI(title="SSL 证书管理", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.auth = auth
    app.state.service = service
    app.state.scheduler = scheduler
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
    templates.env.autoescape = True
    templates.env.filters["local"] = local_time

    # ---------------- guards ----------------

    async def guard(request: Request) -> None:
        if request.url.path.startswith("/static"):
            return
        if not await run_in_threadpool(auth.is_configured):
            raise _http_redirect("/setup")
        if request.url.path in ("/login", "/setup", "/favicon.ico"):
            return
        if not await run_in_threadpool(auth.authenticated, request):
            raise _http_redirect("/login")
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            form = await request.form()
            if not auth.csrf_valid(str(form.get(auth_module.CSRF_FIELD, ""))):
                raise HTTPException(status_code=400, detail="CSRF 校验失败，请刷新页面重新提交")

    def render(request: Request, template: str, status_code: int = 200, **context) -> HTMLResponse:
        with db.session(settings.db_path) as conn:
            values = db.all_settings(conn)
        payload = {
            "request": request,
            "csrf": auth.csrf_token(),
            "notice": request.query_params.get("notice", ""),
            "error": request.query_params.get("error", ""),
            "page": template.removesuffix(".html"),
            "next_run": scheduler.next_run(),
            "ca_label": _ca_label(values),
            "data_dir": str(settings.data_dir),
            "s": values,
            **context,
        }
        return templates.TemplateResponse(
            request=request, name=template, context=payload, status_code=status_code
        )

    # ---------------- public pages ----------------

    @app.get("/setup", response_class=HTMLResponse)
    def setup_page(request: Request):
        if auth.is_configured():
            return _redirect("/login")
        return render(request, "setup.html")

    @app.post("/setup")
    async def setup_submit(request: Request):
        if auth.is_configured():
            raise HTTPException(status_code=400, detail="管理员密码已设置")
        form = await request.form()
        password = str(form.get("password", ""))
        if password != str(form.get("password_confirm", "")):
            return _redirect("/setup?error=" + quote("两次输入的密码不一致"))
        try:
            await run_in_threadpool(auth.set_password, password)
        except ValueError as exc:
            return _redirect("/setup?error=" + quote(str(exc)))
        return _redirect("/login?notice=" + quote("管理员密码已设置，请登录"))

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        if not auth.is_configured():
            return _redirect("/setup")
        if auth.authenticated(request):
            return _redirect("/")
        return render(request, "login.html", locked=0)

    @app.post("/login")
    async def login_submit(request: Request):
        if not auth.is_configured():
            return _redirect("/setup")
        ip = request.client.host if request.client else "unknown"
        locked = auth.locked_out(ip)
        if locked:
            return render(
                request, "login.html", locked=locked, status_code=429,
                error=f"失败次数过多，请 {int(locked / 60) + 1} 分钟后再试",
            )
        form = await request.form()
        value = await run_in_threadpool(auth.login, str(form.get("password", "")), ip)
        if not value:
            return render(request, "login.html", locked=0, status_code=401, error="密码不正确")
        return auth.apply_cookie(_redirect("/"), value)

    @app.post("/logout", dependencies=[Depends(guard)])
    async def logout():
        return auth.logout_response()

    # ---------------- dashboard ----------------

    @app.get("/", dependencies=[Depends(guard)])
    def dashboard(request: Request):
        with db.session(settings.db_path) as conn:
            counters = {
                name: conn.execute(f"SELECT COUNT(*) c FROM {name}").fetchone()["c"]
                for name in ("domains", "credentials", "certificates")
            }
            certs = [_decorate(row) for row in repo.list_certificates(conn)]
            events = conn.execute(
                "SELECT e.*, c.domain FROM events e JOIN certificates ct ON ct.id = e.certificate_id "
                "JOIN domains c ON c.id = ct.domain_id ORDER BY e.id DESC LIMIT 15"
            ).fetchall()
        return render(request, "index.html", counters=counters, certs=certs, events=events)

    # ---------------- credentials ----------------

    @app.get("/credentials", dependencies=[Depends(guard)])
    def credentials_page(request: Request):
        with db.session(settings.db_path) as conn:
            rows = repo.list_credentials(conn)
            used = {
                row["credential_id"]: row["c"]
                for row in conn.execute(
                    "SELECT credential_id, COUNT(*) c FROM domains GROUP BY credential_id"
                ).fetchall()
            }
        items = [
            {
                "row": dict(row),
                "masked": crypto.mask_access_key_id(row["access_key_id"]),
                "domains": used.get(row["id"], 0),
            }
            for row in rows
        ]
        return render(request, "credentials.html", items=items)

    @app.post("/credentials", dependencies=[Depends(guard)])
    async def credential_create(request: Request):
        form = await request.form()
        name = str(form.get("name", "")).strip()
        ak_id = str(form.get("access_key_id", "")).strip()
        ak_secret = str(form.get("access_key_secret", "")).strip()
        if not (name and ak_id and ak_secret):
            return _redirect("/credentials?error=" + quote("名称、AccessKeyId、AccessKeySecret 都要填写"))
        try:
            with db.session(settings.db_path) as conn:
                repo.add_credential(
                    conn, settings.master_key, name, ak_id, ak_secret,
                    str(form.get("eab_kid", "")), str(form.get("eab_hmac_key", "")),
                )
        except sqlite3.IntegrityError:
            return _redirect("/credentials?error=" + quote(f"凭证名称「{name}」已存在"))
        return _redirect("/credentials?notice=" + quote("凭证已保存，AccessKeySecret 已加密写入数据库"))

    @app.post("/credentials/{credential_id}", dependencies=[Depends(guard)])
    async def credential_update(credential_id: int, request: Request):
        form = await request.form()
        name = str(form.get("name", "")).strip()
        ak_id = str(form.get("access_key_id", "")).strip()
        ak_secret = str(form.get("access_key_secret", "")).strip() or None
        if not (name and ak_id):
            return _redirect("/credentials?error=" + quote("名称和 AccessKeyId 不能为空"))
        with db.session(settings.db_path) as conn:
            repo.update_credential(
                conn, settings.master_key, credential_id, name, ak_id, ak_secret,
                str(form.get("eab_kid", "")), str(form.get("eab_hmac_key", "")),
            )
        return _redirect("/credentials?notice=" + quote("凭证已更新"))

    @app.post("/credentials/{credential_id}/delete", dependencies=[Depends(guard)])
    def credential_delete(credential_id: int, request: Request):
        try:
            with db.session(settings.db_path) as conn:
                repo.delete_credential(conn, credential_id)
        except sqlite3.IntegrityError:
            return _redirect("/credentials?error=" + quote("还有域名使用该凭证，请先删除这些域名"))
        return _redirect("/credentials?notice=" + quote("凭证已删除"))

    @app.post("/credentials/{credential_id}/test", dependencies=[Depends(guard)])
    async def credential_test(credential_id: int, request: Request):
        try:
            found = await run_in_threadpool(service.test_dns, credential_id)
        except Exception as exc:
            return _redirect("/credentials?error=" + quote(str(exc)[:400]))
        sample = "、".join(item["domain"] for item in found[:15]) or "（该账号下没有域名）"
        return _redirect(
            "/credentials?notice=" + quote(f"连接成功。账号下共 {len(found)} 个域名：{sample}")
        )

    # ---------------- domains & host records ----------------

    @app.get("/domains", dependencies=[Depends(guard)])
    def domains_page(request: Request):
        with db.session(settings.db_path) as conn:
            rows = repo.list_domains(conn)
            credentials = repo.list_credentials(conn)
            counts = {
                row["domain_id"]: row["c"]
                for row in conn.execute(
                    "SELECT domain_id, COUNT(*) c FROM certificates GROUP BY domain_id"
                ).fetchall()
            }
        items = [{**dict(row), "certificates": counts.get(row["id"], 0)} for row in rows]
        return render(request, "domains.html", items=items, credentials=[dict(c) for c in credentials])

    @app.post("/domains", dependencies=[Depends(guard)])
    async def domain_create(request: Request):
        form = await request.form()
        try:
            domain = names.normalize_domain(str(form.get("domain", "")))
            credential_id = int(str(form.get("credential_id", "0")))
        except ValueError as exc:
            return _redirect("/domains?error=" + quote(str(exc)))
        with db.session(settings.db_path) as conn:
            if repo.get_credential(conn, credential_id) is None:
                return _redirect("/domains?error=" + quote("请先在「阿里云凭证」里添加 AccessKey"))
            try:
                domain_id = repo.add_domain(conn, credential_id, domain)
            except sqlite3.IntegrityError:
                return _redirect("/domains?error=" + quote(f"域名 {domain} 已经存在"))
            repo.add_subname(conn, domain_id, names.APEX)
            repo.add_subname(conn, domain_id, names.WILDCARD)
        return _redirect(f"/domains/{domain_id}?notice=" + quote(f"已添加 {domain}，默认勾选主域名"))

    @app.get("/domains/{domain_id}", dependencies=[Depends(guard)])
    def domain_page(domain_id: int, request: Request):
        with db.session(settings.db_path) as conn:
            domain = repo.get_domain(conn, domain_id)
            if domain is None:
                raise HTTPException(status_code=404, detail="域名不存在")
            subnames = [_describe_subname(domain["domain"], row) for row in repo.list_subnames(conn, domain_id)]
            certificates = [
                _decorate(row) for row in repo.list_certificates(conn) if row["domain_id"] == domain_id
            ]
        rrs = [row["rr"] for row in subnames if row["enabled"]]
        preview, preview_error = _preview_names(domain["domain"], rrs)
        return render(
            request,
            "domain.html",
            domain=dict(domain),
            subnames=subnames,
            preview=preview,
            preview_error=preview_error,
            shared_txt=_shares_txt(subnames),
            certificates=certificates,
            key_types=certstore.KEY_TYPES,
        )

    @app.post("/domains/{domain_id}/delete", dependencies=[Depends(guard)])
    def domain_delete(domain_id: int, request: Request):
        with db.session(settings.db_path) as conn:
            cert_ids = [
                row["id"] for row in conn.execute(
                    "SELECT id FROM certificates WHERE domain_id=?", (domain_id,)
                ).fetchall()
            ]
            repo.delete_domain(conn, domain_id)
        for cert_id in cert_ids:
            _remove_files(certstore.cert_path(settings.cert_dir, cert_id))
        return _redirect("/domains?notice=" + quote("域名已删除，对应的证书文件也已清理"))

    @app.post("/domains/{domain_id}/subnames", dependencies=[Depends(guard)])
    async def subname_add(domain_id: int, request: Request):
        form = await request.form()
        with db.session(settings.db_path) as conn:
            row = conn.execute("SELECT domain FROM domains WHERE id=?", (domain_id,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="域名不存在")
            domain = row["domain"]
            try:
                rr = names.normalize_rr(str(form.get("rr", "")), domain)
                repo.add_subname(conn, domain_id, rr, enabled=True)
            except ValueError as exc:
                return _redirect(f"/domains/{domain_id}?error=" + quote(str(exc)))
        return _redirect(f"/domains/{domain_id}?notice=" + quote(f"已添加 {names.rr_to_fqdn(domain, rr)}"))

    @app.post("/domains/{domain_id}/subnames/toggle", dependencies=[Depends(guard)])
    async def subname_toggle(domain_id: int, request: Request):
        form = await request.form()
        selected = {str(value) for value in form.getlist("rr")}
        with db.session(settings.db_path) as conn:
            for row in repo.list_subnames(conn, domain_id):
                repo.set_subname_enabled(conn, row["id"], row["rr"] in selected)
        return _redirect(
            f"/domains/{domain_id}?notice=" + quote("勾选状态已保存（取消勾选不会删除阿里云解析记录）")
        )

    @app.post("/domains/{domain_id}/subnames/{subname_id}/delete", dependencies=[Depends(guard)])
    def subname_delete(domain_id: int, subname_id: int, request: Request):
        with db.session(settings.db_path) as conn:
            repo.delete_subname(conn, subname_id)
        return _redirect(f"/domains/{domain_id}?notice=" + quote("记录已从列表移除"))

    @app.post("/domains/{domain_id}/import-records", dependencies=[Depends(guard)])
    async def domain_import_records(domain_id: int, request: Request):
        with db.session(settings.db_path) as conn:
            domain = repo.get_domain(conn, domain_id)
            if domain is None:
                raise HTTPException(status_code=404, detail="域名不存在")
            credential_id, name = domain["credential_id"], domain["domain"]
            existing = {row["rr"].lower() for row in repo.list_subnames(conn, domain_id)}
        try:
            records = await run_in_threadpool(_fetch_records, settings, credential_id, name)
        except Exception as exc:
            return _redirect(f"/domains/{domain_id}?error=" + quote(str(exc)[:400]))
        found: set[str] = set()
        skipped = 0
        for record in records:
            try:
                rr = names.normalize_rr(record.rr, name)
            except ValueError:
                skipped += 1
                continue
            if rr.lower() not in existing:
                found.add(rr)
        with db.session(settings.db_path) as conn:
            for rr in sorted(found):
                repo.add_subname(conn, domain_id, rr, enabled=False)
        note = f"从阿里云导入 {len(found)} 条主机记录（默认未勾选）"
        if skipped:
            note += f"，另有 {skipped} 条记录名不能用作证书域名，已跳过"
        return _redirect(f"/domains/{domain_id}?notice=" + quote(note))

    @app.post("/domains/{domain_id}/issue", dependencies=[Depends(guard)])
    async def domain_issue(domain_id: int, request: Request):
        form = await request.form()
        rrs = [str(value) for value in form.getlist("rr")]
        key_type = str(form.get("key_type", "rsa2048"))
        if key_type not in certstore.KEY_TYPES:
            key_type = "rsa2048"
        if not rrs:
            return _redirect(f"/domains/{domain_id}?error=" + quote("请至少勾选一个域名或子域名"))
        with db.session(settings.db_path) as conn:
            domain = repo.get_domain(conn, domain_id)
            if domain is None:
                raise HTTPException(status_code=404, detail="域名不存在")
            try:
                sans = names.build_names(domain["domain"], rrs)
            except ValueError as exc:
                return _redirect(f"/domains/{domain_id}?error=" + quote(str(exc)))
            certificate_id = repo.create_certificate(
                conn, domain_id, sans, key_type, service.ca_directory_url()
            )
            repo.log_event(conn, certificate_id, "info", "任务已排队，等待签发")
        note = f"证书 #{certificate_id} 开始申请" if service.start_issue(certificate_id) else "已有相同任务在运行"
        return _redirect(f"/certificates/{certificate_id}?notice=" + quote(note))

    # ---------------- certificates ----------------

    @app.get("/certificates", dependencies=[Depends(guard)])
    def certificates_page(request: Request):
        with db.session(settings.db_path) as conn:
            certs = [_decorate(row) for row in repo.list_certificates(conn)]
        return render(request, "certificates.html", certs=certs)

    @app.get("/certificates/{certificate_id}", dependencies=[Depends(guard)])
    def certificate_page(certificate_id: int, request: Request):
        with db.session(settings.db_path) as conn:
            cert = repo.get_certificate(conn, certificate_id)
            if cert is None:
                raise HTTPException(status_code=404, detail="证书不存在")
            events = [dict(row) for row in repo.list_events(conn, certificate_id, limit=300)]
        directory = certstore.cert_path(settings.cert_dir, certificate_id)
        return render(
            request,
            "certificate.html",
            cert=_decorate(cert),
            files=[
                {
                    "kind": kind,
                    "name": certstore.FILE_NAMES[kind],
                    "exists": (directory / certstore.FILE_NAMES[kind]).is_file(),
                }
                for kind in ("fullchain", "cert", "key", "chain")
            ],
            events=list(reversed(events)),
            last_event_id=events[-1]["id"] if events else 0,
            directory=str(directory),
            key_types=certstore.KEY_TYPES,
        )

    @app.get("/certificates/{certificate_id}/events", dependencies=[Depends(guard)])
    def certificate_events(certificate_id: int, after: int = 0):
        with db.session(settings.db_path) as conn:
            rows = repo.list_events(conn, certificate_id, after_id=max(0, after))
            cert = repo.get_certificate(conn, certificate_id)
        if cert is None:
            raise HTTPException(status_code=404, detail="证书不存在")
        return JSONResponse(
            {
                "events": [
                    {**dict(row), "created_at": local_time(row["created_at"], seconds=True)}
                    for row in rows
                ],
                "status": cert["status"],
                "not_after": cert["not_after"],
                "error": cert["error"],
            }
        )

    @app.post("/certificates/{certificate_id}/renew", dependencies=[Depends(guard)])
    def certificate_renew(certificate_id: int, request: Request):
        with db.session(settings.db_path) as conn:
            if repo.get_certificate(conn, certificate_id) is None:
                raise HTTPException(status_code=404, detail="证书不存在")
            repo.log_event(conn, certificate_id, "info", "手动触发续期/重新申请")
        note = "已开始重新申请" if service.start_issue(certificate_id) else "已有任务在运行，请稍候"
        return _redirect(f"/certificates/{certificate_id}?notice=" + quote(note))

    @app.post("/certificates/{certificate_id}/revoke", dependencies=[Depends(guard)])
    async def certificate_revoke(certificate_id: int, request: Request):
        try:
            await run_in_threadpool(service.revoke, certificate_id)
        except Exception as exc:
            return _redirect(f"/certificates/{certificate_id}?error=" + quote(str(exc)[:400]))
        return _redirect(f"/certificates/{certificate_id}?notice=" + quote("证书已吊销"))

    @app.post("/certificates/{certificate_id}/delete", dependencies=[Depends(guard)])
    def certificate_delete(certificate_id: int, request: Request):
        with db.session(settings.db_path) as conn:
            repo.delete_certificate(conn, certificate_id)
        _remove_files(certstore.cert_path(settings.cert_dir, certificate_id))
        return _redirect("/certificates?notice=" + quote("证书记录与磁盘文件已删除"))

    @app.get("/certificates/{certificate_id}/download", dependencies=[Depends(guard)])
    async def certificate_download(certificate_id: int, request: Request, kind: str = "fullchain"):
        directory = certstore.cert_path(settings.cert_dir, certificate_id)
        password = request.query_params.get("password", "")
        try:
            if kind == "zip":
                payload, filename, media = _build_zip(directory), f"cert-{certificate_id}.zip", "application/zip"
            elif kind == "pfx":
                secret = password or _stored_pfx_password(settings.db_path)
                if not secret:
                    raise HTTPException(
                        status_code=400,
                        detail="导出 PFX 需要密码：请在「设置」里填写 PFX 密码，或在链接后加 ?password=你的密码",
                    )
                payload, filename, media = (
                    await run_in_threadpool(certstore.as_pfx, directory, secret.encode()),
                    f"cert-{certificate_id}.pfx",
                    "application/pkcs12",
                )
            elif kind == "der":
                payload, filename, media = (
                    await run_in_threadpool(certstore.as_der, directory),
                    f"cert-{certificate_id}.cer",
                    "application/octet-stream",
                )
            else:
                payload, filename, media = (
                    await run_in_threadpool(certstore.read, directory, kind),
                    f"cert-{certificate_id}-{certstore.FILE_NAMES[kind]}",
                    "application/x-pem-file",
                )
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return Response(
            content=payload,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    # ---------------- settings ----------------

    @app.get("/settings", dependencies=[Depends(guard)])
    def settings_page(request: Request):
        with db.session(settings.db_path) as conn:
            values = db.all_settings(conn)
        return render(
            request,
            "settings.html",
            values={**values, **{key: "" for key in SECRET_SETTINGS}},
            ca_urls=config_module.CA_DIRECTORY_URLS,
            key_types=certstore.KEY_TYPES,
            account_key=str(settings.account_key_path),
            secret_state={key: bool(values.get(key)) for key in SECRET_SETTINGS},
        )

    @app.post("/settings", dependencies=[Depends(guard)])
    async def settings_submit(request: Request):
        form = await request.form()
        updates: dict[str, str] = {}
        for key in EDITABLE_SETTINGS:
            if key not in form:
                continue
            value = str(form.get(key, "")).strip()
            if key in SWITCH_SETTINGS:
                value = "1" if value in ("1", "on", "true") else "0"
            if key in SECRET_SETTINGS and not value:
                continue
            if key in NUMERIC_LIMITS:
                low, high = NUMERIC_LIMITS[key]
                try:
                    number = int(value)
                except ValueError:
                    return _redirect("/settings?error=" + quote(f"{key} 必须是整数"))
                if not low <= number <= high:
                    return _redirect("/settings?error=" + quote(f"{key} 应在 {low}~{high} 之间"))
            if key == "contact_email" and value and "@" not in value:
                return _redirect("/settings?error=" + quote("联系邮箱格式不正确"))
            if key == "ca_directory" and value and not value.startswith("https://"):
                return _redirect("/settings?error=" + quote("自定义 CA 目录必须以 https:// 开头"))
            updates[key] = value
        with db.session(settings.db_path) as conn:
            for key, value in updates.items():
                db.set_setting(conn, key, value)
        scheduler.reschedule()
        return _redirect("/settings?notice=" + quote("设置已保存"))

    @app.post("/settings/test-ca", dependencies=[Depends(guard)])
    async def settings_test_ca(request: Request):
        try:
            text = await run_in_threadpool(service.test_account)
        except Exception as exc:
            return _redirect("/settings?error=" + quote(str(exc)[:400]))
        return _redirect("/settings?notice=" + quote(text))

    @app.post("/settings/test-smtp", dependencies=[Depends(guard)])
    async def settings_test_smtp(request: Request):
        with db.session(settings.db_path) as conn:
            mail = notify.build_mail_config(db.all_settings(conn))
        try:
            await run_in_threadpool(
                notify.send, mail, "来自证书管理平台的测试邮件", "收到这封邮件说明 SMTP 配置可用。"
            )
        except Exception as exc:
            return _redirect("/settings?error=" + quote(f"发信失败：{exc}"[:400]))
        return _redirect("/settings?notice=" + quote("测试邮件已发出"))

    @app.post("/settings/change-password", dependencies=[Depends(guard)])
    async def settings_change_password(request: Request):
        form = await request.form()
        if not auth.check_password(str(form.get("current_password", ""))):
            return _redirect("/settings?error=" + quote("当前密码不正确"))
        try:
            await run_in_threadpool(auth.set_password, str(form.get("password", "")))
        except ValueError as exc:
            return _redirect("/settings?error=" + quote(str(exc)))
        return auth.logout_response()

    return app


# ---------------- helpers ----------------


def _redirect(location: str) -> RedirectResponse:
    return RedirectResponse(location, status_code=303)


def _http_redirect(location: str) -> HTTPException:
    return HTTPException(status_code=303, detail="需要登录", headers={"Location": location})


def _preview_names(domain: str, rrs: list[str]) -> tuple[list[str], str]:
    try:
        return names.build_names(domain, rrs), ""
    except ValueError as exc:
        return [], str(exc)


def _describe_subname(domain: str, row) -> dict:
    item = dict(row)
    item["fqdn"] = names.rr_to_fqdn(domain, row["rr"])
    item["txt"] = names.txt_fqdn(item["fqdn"])
    return item


def _shares_txt(subnames: list[dict]) -> bool:
    """Apex and wildcard validate through the same TXT name (two records, two values)."""
    seen: set[str] = set()
    for row in subnames:
        if row["txt"] in seen:
            return True
        seen.add(row["txt"])
    return False


def _remaining(not_after: str | None) -> int | None:
    parsed = certstore.parse_iso(not_after or "")
    if parsed is None:
        return None
    return certstore.days_left(parsed, datetime.datetime.now(datetime.timezone.utc))


def _decorate(row) -> dict:
    item = dict(row)
    item["name_list"] = db.load_json(item.get("names"), []) or []
    item["remaining"] = _remaining(item.get("not_after"))
    item["updated_display"] = local_time(item.get("updated_at"), seconds=True)
    item["not_after_display"] = local_time(item.get("not_after"))
    return item


def local_time(raw: str | None, seconds: bool = False) -> str:
    """Timestamps are stored as UTC ISO strings; render them in the server's local zone."""
    parsed = certstore.parse_iso(raw or "")
    if parsed is None:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M")


def _stored_pfx_password(db_path: Path) -> str:
    with db.session(db_path) as conn:
        return db.get_setting(conn, "pfx_password", "")


def _fetch_records(settings: config_module.Settings, credential_id: int, domain: str) -> list:
    with db.session(settings.db_path) as conn:
        ak_id, ak_secret = repo.open_access_key(conn, settings.master_key, credential_id)
    return alidns.AliDns(ak_id, ak_secret).list_records(domain)


def _build_zip(directory: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for kind in ("fullchain", "cert", "key", "chain"):
            target = directory / certstore.FILE_NAMES[kind]
            if target.is_file():
                archive.write(target, arcname=certstore.FILE_NAMES[kind])
        archive.writestr(
            "README.txt",
            f"证书目录：{directory}\n导出时间：{datetime.datetime.now().isoformat(timespec='seconds')}\n"
            "privkey.pem 是私钥，请通过安全渠道传输，不要上传到公开位置。\n",
        )
    return buffer.getvalue()


def _remove_files(directory: Path) -> None:
    if not directory.is_dir():
        return
    for child in directory.iterdir():
        try:
            child.unlink()
        except OSError:
            logger.warning("无法删除 %s", child)
    with contextlib.suppress(OSError):
        directory.rmdir()


def _ca_label(values: dict[str, str]) -> str:
    custom = values.get("ca_directory", "").strip()
    if custom:
        return f"自定义（{custom}）"
    name = values.get("ca_name", "letsencrypt-staging")
    if "staging" in name:
        return f"{name} —— 测试环境，签发的证书不被浏览器信任"
    return name
