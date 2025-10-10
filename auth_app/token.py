from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone  # Django timezone.now() এর জন্য
from datetime import datetime, timedelta, timezone as dt_timezone  # Python এর timezone

from django.utils.http import base36_to_int

class TokenGenerator(PasswordResetTokenGenerator):
    def __init__(self, expiry_minutes):
        self.expiry_minutes = expiry_minutes
        super().__init__()

    def check_token(self, user, token):
        if not super().check_token(user, token):
            return False

        try:
            ts_b36 = token.split("-")[0]
            ts = base36_to_int(ts_b36)
        except (ValueError, IndexError):
            return False

        # Timestamp is seconds since 2001‑01‑01 UTC
        token_time = datetime(2001, 1, 1, tzinfo=dt_timezone.utc) + timedelta(seconds=ts)
        now = timezone.now()

        if now - token_time > timedelta(minutes=self.expiry_minutes):
            return False

        return True
