"""Daily renewal + expiry warning jobs (APScheduler, single-process)."""

from __future__ import annotations

import datetime
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .service import Service

logger = logging.getLogger(__name__)


class Scheduler:
    def __init__(self, service: Service):
        self.service = service
        self._scheduler = BackgroundScheduler()
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        hour = self.service.int_setting("renewal_hour", 3)
        self._scheduler.add_job(
            self.run_jobs, CronTrigger(hour=hour, minute=10), id="renew-and-notify", max_instances=1
        )
        # Catch up shortly after a restart so a freshly deployed server does not wait until 03:10.
        self._scheduler.add_job(
            self.run_jobs,
            "date",
            run_date=datetime.datetime.now() + datetime.timedelta(seconds=45),
            id="startup-scan",
            max_instances=1,
        )
        self._scheduler.start()
        self._started = True
        logger.info("自动续期任务已启动，每天 %02d:10 运行", hour)

    def reschedule(self) -> None:
        """Apply a new renewal_hour from the settings page."""
        if not self._started:
            return
        hour = self.service.int_setting("renewal_hour", 3)
        self._scheduler.reschedule_job(
            "renew-and-notify", trigger=CronTrigger(hour=hour, minute=10)
        )

    def run_jobs(self) -> dict:
        started = self.service.renew_due()
        if started:
            logger.info("自动续期已启动 %d 个任务：%s", len(started), started)
        warned = 0
        try:
            warned = self.service.notify_warnings()
        except Exception:
            logger.exception("到期提醒邮件发送失败")
        return {"started": started, "warned": warned}

    def next_run(self) -> str:
        if not self._started:
            return "未启动"
        job = self._scheduler.get_job("renew-and-notify")
        if job is None or job.next_run_time is None:
            return "未安排"
        return job.next_run_time.isoformat(timespec="minutes")

    def stop(self) -> None:
        if self._started:
            self._scheduler.shutdown(wait=False)
            self._started = False
