#!/usr/bin/env bash
# نصب xui-reseller روی همان VPS ی که ثنایی (3x-ui) دارد
set -e
[ "$(id -u)" -ne 0 ] && { echo "با root اجرا کنید: sudo bash install.sh"; exit 1; }

APP_DIR=/opt/xui-reseller
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

apt-get update -y >/dev/null
apt-get install -y python3 python3-venv python3-pip >/dev/null

mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/app.py" "$SRC_DIR/static" "$SRC_DIR/requirements.txt" "$APP_DIR/"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

ask() { # ask VAR "prompt" "default"
  local v; read -r -p "$2 [$3]: " v < /dev/tty || true
  printf -v "$1" '%s' "${v:-$3}"
}
rnd() { python3 -c "import secrets;print(secrets.token_hex($1))"; }

if [ ! -f "$APP_DIR/.env" ]; then
  echo "از کاراکترهای \" ' \\ \$ در مقادیر استفاده نکنید."
  ask PANEL_URL  "آدرس پنل ثنایی (با webBasePath، بدون اسلش آخر)" "http://127.0.0.1:2053"
  ask PANEL_USER "یوزر پنل ثنایی" "admin"
  ask PANEL_PASS "پسورد پنل ثنایی" "admin"
  ask SUDO_USER  "یوزر مالک ریسلر پنل" "owner"
  ask SUDO_PASS  "پسورد مالک ریسلر پنل" "$(rnd 6)"
  ask SUB_URL_BASE "آدرس پایه ساب‌اسکریپشن ثنایی (مثال https://domain:2096/sub/ ؛ می‌تواند خالی باشد)" ""
  ask PORT "پورت ریسلر پنل" "8088"
  cat > "$APP_DIR/.env" <<ENV
PANEL_URL="$PANEL_URL"
PANEL_USER="$PANEL_USER"
PANEL_PASS="$PANEL_PASS"
SUDO_USER="$SUDO_USER"
SUDO_PASS="$SUDO_PASS"
SECRET_KEY="$(rnd 32)"
SUB_URL_BASE="$SUB_URL_BASE"
PORT="$PORT"
COOKIE_SECURE="0"
DB_PATH="$APP_DIR/data.db"
ENV
  chmod 600 "$APP_DIR/.env"
fi

set -a; . "$APP_DIR/.env"; set +a

cat > /etc/systemd/system/xui-reseller.service <<UNIT
[Unit]
Description=xui-reseller
After=network.target

[Service]
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/uvicorn app:app --host 0.0.0.0 --port $PORT
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now xui-reseller
systemctl restart xui-reseller

echo
echo "نصب شد. آدرس: http://IP-سرور:$PORT"
echo "یوزر مالک: $SUDO_USER"
echo "پسورد مالک: $SUDO_PASS"
echo "پورت $PORT را در فایروال باز کنید (ufw allow $PORT). برای امنیت بهتر پشت HTTPS قرار دهید."
echo "لاگ‌ها: journalctl -u xui-reseller -f"
