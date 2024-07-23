import time
import pyotp

import pyotp

otp_secret = 'FO5EAXMMFD4QCHRECFWNLRP4Y3NKB4CS'  # The OTP secret for the testuser
totp = pyotp.TOTP(otp_secret)
print("Current OTP:", totp.now())
