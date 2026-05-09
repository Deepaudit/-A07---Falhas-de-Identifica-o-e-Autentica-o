# 🔑 A07 - Falhas de Identificação e Autenticação

## 📖 Teoria (20%)

Falhas que permitem ao atacante comprometer senhas, chaves ou tokens de sessão, ou explorar falhas de implementação para assumir identidades de outros usuários.

---

## 💻 Prática (80%)

### 🔴 Vulnerável — JWT sem verificação

```python
import jwt

# ❌ CRÍTICO: aceitar algoritmo "none" 
def verify_token_bad(token: str):
    # Permite alg:none → token sem assinatura é aceito!
    return jwt.decode(token, options={"verify_signature": False})

# Exploração:
# 1. Decodifique o JWT (base64)
# 2. Altere o payload: {"user": "attacker", "role": "admin"}
# 3. Altere o header: {"alg": "none"}
# 4. Envie sem assinatura
```

**Exploração de JWT:**
```bash
# jwt_tool — ferramenta completa para JWT
python3 jwt_tool.py TOKEN -X a   # Algoritmo none
python3 jwt_tool.py TOKEN -X s   # HMAC confusão (RS256→HS256)
python3 jwt_tool.py TOKEN -C -d rockyou.txt  # Crack de secret fraco

# Manual:
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
payload = base64.b64encode(json.dumps({"user":"admin","role":"admin"}).encode()).decode().rstrip("=")
forged_token = f"{header}.{payload}."  # Sem assinatura!
```

### 🟢 Seguro — JWT com verificação correta

```python
from datetime import datetime, timedelta
import jwt
from typing import Optional

SECRET_KEY = os.environ.get("JWT_SECRET")  # 256+ bits
ALGORITHM = "HS256"

def create_token(user_id: int, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),  # ✅ Expiração curta
        "jti": secrets.token_hex(16),  # ✅ ID único (previne replay)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],  # ✅ Algoritmo explícito, nunca ["none"]
            options={
                "require": ["exp", "iat", "sub"],  # ✅ Claims obrigatórios
                "verify_exp": True,
            }
        )
        
        # ✅ Verificar blacklist (tokens revogados)
        if is_token_revoked(payload["jti"]):
            return None
            
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ✅ Blacklist de tokens (logout)
revoked_tokens = set()

def revoke_token(jti: str):
    revoked_tokens.add(jti)

def is_token_revoked(jti: str) -> bool:
    return jti in revoked_tokens
```

---

### 🔴 Vulnerável — Sessão sem expiração

```python
from flask import Flask, session

app = Flask(__name__)
app.secret_key = "chave_fraca"  # ❌ Chave previsível

@app.route("/login", methods=["POST"])
def login():
    # ❌ Sessão não expira nunca
    # ❌ Sem regeneração de session ID
    session["user_id"] = user.id
    return redirect("/dashboard")
```

### 🟢 Seguro — Sessão com boas práticas

```python
from flask import Flask, session
from datetime import timedelta
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # ✅ Chave forte e aleatória

# ✅ Configurações de sessão segura
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_COOKIE_SECURE=True,       # ✅ Apenas HTTPS
    SESSION_COOKIE_HTTPONLY=True,     # ✅ Sem acesso por JavaScript
    SESSION_COOKIE_SAMESITE="Strict", # ✅ Proteção CSRF
)

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user:
        # ✅ Regenerar session ID após login (previne session fixation)
        session.clear()
        session["user_id"] = user.id
        session["role"] = user.role
        session["login_time"] = datetime.utcnow().isoformat()
        session.permanent = True
        return redirect("/dashboard")
    return "Inválido", 401

@app.route("/logout")
def logout():
    # ✅ Destruir sessão completamente
    session.clear()
    return redirect("/login")
```

---

### 🟢 MFA — Autenticação Multi-Fator

```python
import pyotp
import qrcode

class MFAService:
    @staticmethod
    def generate_secret() -> str:
        # ✅ Gerar secret TOTP para o usuário
        return pyotp.random_base32()
    
    @staticmethod
    def get_qr_code(user_email: str, secret: str) -> str:
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name="MeuApp"
        )
        # Gerar QR code para o Google Authenticator
        img = qrcode.make(provisioning_uri)
        img.save(f"/tmp/qr_{user_email}.png")
        return provisioning_uri
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        totp = pyotp.TOTP(secret)
        # ✅ valid_window=1 aceita código com 30s de diferença de clock
        return totp.verify(code, valid_window=1)

@app.route("/login/mfa", methods=["POST"])
def verify_mfa():
    user_id = session.get("pending_mfa_user")
    mfa_code = request.form["code"]
    
    user = User.query.get(user_id)
    
    if MFAService.verify_totp(user.mfa_secret, mfa_code):
        # ✅ MFA válido — completar login
        session.clear()
        session["user_id"] = user.id
        return redirect("/dashboard")
    
    return jsonify({"error": "Código inválido"}), 401
```

---

### 🛠️ Ferramentas

```bash
# Hydra — brute force de login
hydra -l admin -P rockyou.txt http-post-form \
      "//login:user=^USER^&pass=^PASS^:Invalid credentials"

# jwt_tool — análise e ataque de JWT
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -h

# Hashcat — crackear secrets de JWT
hashcat -a 0 -m 16500 jwt.txt rockyou.txt

# Burp Suite — session analysis
# Extensions: JWT Editor, Session Auth Tester
```

---

### ✅ Checklist de Prevenção

- [ ] MFA habilitado para contas privilegiadas
- [ ] JWT com algoritmo explícito e nunca "none"
- [ ] Expiração de tokens curta (access: 1h, refresh: 7d)
- [ ] Session ID regenerado após autenticação
- [ ] Cookies com Secure + HttpOnly + SameSite
- [ ] Rate limiting em endpoints de autenticação
- [ ] Senhas verificadas contra listas de senhas comuns
- [ ] Não revelar se username existe na mensagem de erro
