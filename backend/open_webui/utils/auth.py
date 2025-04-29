import logging
import uuid
import jwt
import base64
import hmac
import hashlib
import requests
import os



from datetime import datetime, timedelta
import pytz
from pytz import UTC
from typing import Optional, Union, List, Dict

from open_webui.models.users import Users

from open_webui.constants import ERROR_MESSAGES
from open_webui.env import (
    WEBUI_SECRET_KEY,
    TRUSTED_SIGNATURE_KEY,
    STATIC_DIR,
    SRC_LOG_LEVELS,
)

from fastapi import BackgroundTasks, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

import json
import base64
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


logging.getLogger("passlib").setLevel(logging.ERROR)

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["OAUTH"])

SESSION_SECRET = WEBUI_SECRET_KEY
ALGORITHM = "HS256"

PRIVATE_KEY_PEM = '''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCer8pCiQPBYD0HDUrHwVe0WJUAMSi1KOokZI9cS5w7zr1h/0f3viZWH67ZHn50eOK3UfjHc4VRlEEl+p2MBnFOz+W3vqnb7C0LSzCJ64+J0W+Nmh2mXz/a5CBqOpG5st3/qoLWnFm3dvdVuPSQ5viar9U1izO5DRRFuqG50UbpE98pBEx44dJo/XMRomfNq7Az3m5175nJzDzbnr+ZxANA8kVOf+C0/aUy+wEdXVnBSrqfP5w8Vw3JeUVOFaHChVy44DG/eDdtak9dFLojykn2E4zuLXZicGMvFP8eaxxEGxm+9BkRV1c6WAkzFM5EkOXw1awRcDJmnL2AvOZp7V+hAgMBAAECggEAAUQIMjsrDUASBIwh2FGNvEnHmHqL51QF+BfYP+V3f8+gmZdCcPKylhXHHIK+gfnT3x/3gsnEWrf6xA2Jc6w6e6UzYSGTc8ZgvpoRL0xydug1glTkHydb2EhhDM/eSTOoyykGRaV2Hr1DcErbIovBGGTGJ9juJu/4hSzdrOCDNwk3EQkQPlcFF0dWM4oZ2RhA9m6DdARsytklf3PuPfGJC64clNleaXv19HyVXEPD6x16wH0H3namShGREpVqROp1nKOb5iQMRLAsq6e2GUliEtP7jMz8dxrknEejnVRHBTmxCVn1ePW8nOLUaHWI7Rb8pmk/NWsXAu9f9zNaVVtzJQKBgQDaDe4vt7dRkp/LafMOd5NAkUPkqOJHbUqV/VnE5nXcnNonUiMTFwMCTxU03DTNMuUkLkt2iCrEccVu8D0BX3/KXJX5dfUmakxnm/u2baWdXWdY9/NlPPK2Ow+Bl3JoPG7IKs/t6Dd4si+UqurE3FvfiDc7Jyd++IRGpBrSH9fRxQKBgQC6TRirT0zRP+96arCBhQ77HSrRCjQ5noaf11Nz95uIHJw2fawhzFHV+BRlXZ919x++29GRz9U83tAMptH3BvcciP2uzImZhx+wQTd/XcIQhJEVVo+jKP0E5TUqx8ohmly704/eze86qT37L25JQRKBQV6YvwrojV7o7dy00F+ALQKBgFrcxSzzJBuEurt7mcGkiCK2pZDp4uianSLlIHwRAHn+jlUmP+FbjHBw3chaHlKHa75o4B8zXIbhVcEFsJYa4lhDvmbmBVKNpurhr8Dz7bgmTMNhBvZfsE/JSovYvN68l/knBeAADOVpcrRDiHKh1FLQIxuuFCIvkocRKO/4Pul1AoGAH5/4wRPcEWVODLTRs5rXuS7xVrzpsqJDbhzKUNRGdauNpP5eWvppJe5P4AktiYPiwq5j++GQ7B1SqeMjn1ByYEis76BO913ltjDL7/YFfHJUgo/IIEVT9iHGjbWOjXe7qDK4qHTC2G1kVSBvE0ZVktV67mj3vBRLeTTvk04P+B0CgYEAx6Ahiiq1jCI5aRXpIUB3IpvUj7i8AgjfhHY/tWpSBhw20QO6lgoZBF3XJAE9RQuhRozbvXrH0HmcnpmBHJHyQlkgyf5WTcyox6RPPANHz+Lw1WOWEQKcpK2Ij3QHC8u33Yc3uTZnuKVl01yq7GbzgxGAjqOkDgpVZYOBzfdbA1s=
-----END PRIVATE KEY-----'''

##############
# Auth Utils
##############


def verify_signature(payload: str, signature: str) -> bool:
    """
    Verifies the HMAC signature of the received payload.
    """
    try:
        expected_signature = base64.b64encode(
            hmac.new(TRUSTED_SIGNATURE_KEY, payload.encode(), hashlib.sha256).digest()
        ).decode()

        # Compare securely to prevent timing attacks
        return hmac.compare_digest(expected_signature, signature)

    except Exception:
        return False


def override_static(path: str, content: str):
    # Ensure path is safe
    if "/" in path or ".." in path:
        log.error(f"Invalid path: {path}")
        return

    file_path = os.path.join(STATIC_DIR, path)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, "wb") as f:
        f.write(base64.b64decode(content))  # Convert Base64 back to raw binary


def get_license_data(app, key):
    if key:
        try:
            res = requests.post(
                "https://api.openwebui.com/api/v1/license/",
                json={"key": key, "version": "1"},
                timeout=5,
            )

            if getattr(res, "ok", False):
                payload = getattr(res, "json", lambda: {})()
                for k, v in payload.items():
                    if k == "resources":
                        for p, c in v.items():
                            globals().get("override_static", lambda a, b: None)(p, c)
                    elif k == "count":
                        setattr(app.state, "USER_COUNT", v)
                    elif k == "name":
                        setattr(app.state, "WEBUI_NAME", v)
                    elif k == "metadata":
                        setattr(app.state, "LICENSE_METADATA", v)
                return True
            else:
                log.error(
                    f"License: retrieval issue: {getattr(res, 'text', 'unknown error')}"
                )
        except Exception as ex:
            log.exception(f"License: Uncaught Exception: {ex}")
    return False


bearer_security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return (
        pwd_context.verify(plain_password, hashed_password) if hashed_password else None
    )


def get_password_hash(password):
    return pwd_context.hash(password)


def create_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    payload = data.copy()

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
        payload.update({"exp": expire})

    encoded_jwt = jwt.encode(payload, SESSION_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    try:
        decoded = jwt.decode(token, SESSION_SECRET, algorithms=[ALGORITHM])
        return decoded
    except Exception:
        return None


def extract_token_from_auth_header(auth_header: str):
    return auth_header[len("Bearer ") :]


def create_api_key():
    key = str(uuid.uuid4()).replace("-", "")
    return f"sk-{key}"


def get_http_authorization_cred(auth_header: Optional[str]):
    if not auth_header:
        return None
    try:
        scheme, credentials = auth_header.split(" ")
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)
    except Exception:
        return None


def get_current_user(
    request: Request,
    background_tasks: BackgroundTasks,
    auth_token: HTTPAuthorizationCredentials = Depends(bearer_security),
):
    token = None

    if auth_token is not None:
        token = auth_token.credentials

    if token is None and "token" in request.cookies:
        token = request.cookies.get("token")

    if token is None:
        raise HTTPException(status_code=403, detail="Not authenticated")

    # auth by api key
    if token.startswith("sk-"):
        if not request.state.enable_api_key:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.API_KEY_NOT_ALLOWED
            )

        if request.app.state.config.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS:
            allowed_paths = [
                path.strip()
                for path in str(
                    request.app.state.config.API_KEY_ALLOWED_ENDPOINTS
                ).split(",")
            ]

            # Check if the request path matches any allowed endpoint.
            if not any(
                request.url.path == allowed
                or request.url.path.startswith(allowed + "/")
                for allowed in allowed_paths
            ):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.API_KEY_NOT_ALLOWED
                )

        return get_current_user_by_api_key(token)

    # auth by jwt token
    try:
        data = decode_token(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    if data is not None and "id" in data:
        user = Users.get_user_by_id(data["id"])
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.INVALID_TOKEN,
            )
        else:
            # Refresh the user's last active timestamp asynchronously
            # to prevent blocking the request
            if background_tasks:
                background_tasks.add_task(Users.update_user_last_active_by_id, user.id)
        return user
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )


def get_current_user_by_api_key(api_key: str):
    user = Users.get_user_by_api_key(api_key)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN,
        )
    else:
        Users.update_user_last_active_by_id(user.id)

    return user


def get_verified_user(user=Depends(get_current_user)):
    if user.role not in {"user", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user


def get_admin_user(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user


def decrypt_userinfo(token: str) -> str:
    # 解析JSON token
    payload = json.loads(token)
    encrypted_aes_key_b64 = payload['encrypted_key']
    iv_b64 = payload['iv']
    ciphertext_b64 = payload['ciphertext']
    hmac_b64 = payload['hmac']

    # Base64解码各字段
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    received_hmac = base64.b64decode(hmac_b64)

    # 加载RSA私钥
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode(),
        password=None,
        backend=default_backend()
    )

    # RSA解密获取AES密钥
    aes_key_bytes = private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 验证HMAC
    hmac_calculator = hmac.new(aes_key_bytes, ciphertext, 'sha256')
    calculated_hmac = hmac_calculator.digest()
    if not hmac.compare_digest(calculated_hmac, received_hmac):
        raise ValueError("HMAC verification failed")

    # AES解密
    cipher = AES.new(aes_key_bytes, AES.MODE_CBC, iv=iv)
    decrypted_data = cipher.decrypt(ciphertext)
    decrypted_data = unpad(decrypted_data, AES.block_size)

    return decrypted_data.decode('utf-8')