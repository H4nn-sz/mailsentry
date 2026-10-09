"""Graba un video de demostración de MailSentry (~1 minuto) recorriendo la demo de forma automática.

Requisitos (solo para grabar, no para usar MailSentry):
    pip install playwright imageio-ffmpeg
    python -m playwright install chromium
    python main.py demo            # genera la empresa de demostración

Uso:
    python herramientas/grabar_demo.py
Resultado: medios/mailsentry-demo.mp4 (1600x900, H.264)
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import imageio_ffmpeg
from playwright.sync_api import sync_playwright

RAIZ = Path(__file__).resolve().parent.parent
PUERTO = 8051
BASE = f"http://127.0.0.1:{PUERTO}"
ANCHO, ALTO = 1600, 900
SALIDA = RAIZ / "medios" / "mailsentry-demo.mp4"

CORREO_PRUEBA = """Authentication-Results: mx1.textilesdelsur.example; spf=pass smtp.mailfrom=interbank-alertas.top; dkim=none; dmarc=none
Received: from mail.interbank-alertas.top (mail.interbank-alertas.top [198.51.100.67]) by mx1.textilesdelsur.example; Thu, 08 Oct 2026 09:12:00 -0500
From: "Interbank - Seguridad" <alertas@interbank-alertas.top>
To: andrea.rios@textilesdelsur.example
Subject: Su tarjeta ha sido bloqueada temporalmente
Date: Thu, 08 Oct 2026 09:12:00 -0500
Message-ID: <video-demo-001@interbank-alertas.top>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Estimado cliente:</p><p>Por seguridad su tarjeta fue bloqueada. Para desbloquear su cuenta ingrese su clave de internet en las próximas 24 horas:</p><p><a href="https://interbank-desbloqueo.web.app/acceso">https://interbank.pe/desbloqueo</a></p>"""

# Subtítulos y cursor visibles en el video (Playwright no graba el puntero real)
EXTRAS = """
(() => {
  const crear = () => {
    if (document.getElementById('__cursor')) return;
    const c = document.createElement('div'); c.id = '__cursor';
    Object.assign(c.style, {position:'fixed', zIndex:2147483647, width:'18px', height:'18px', borderRadius:'50%',
      border:'2px solid #fff', background:'rgba(229,103,43,.55)', pointerEvents:'none', left:'-40px', top:'-40px',
      transform:'translate(-50%,-50%)', transition:'left .05s linear, top .05s linear', boxShadow:'0 0 10px rgba(0,0,0,.6)'});
    document.body.appendChild(c);
    document.addEventListener('mousemove', e => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
  };
  window.__subtitulo = (texto) => {
    let s = document.getElementById('__sub');
    if (!s) {
      s = document.createElement('div'); s.id = '__sub';
      Object.assign(s.style, {position:'fixed', left:'50%', bottom:'34px', transform:'translateX(-50%)', zIndex:2147483646,
        background:'rgba(8,8,8,.86)', color:'#fff', font:'600 22px system-ui, Segoe UI, sans-serif', padding:'12px 22px',
        borderRadius:'12px', border:'1px solid rgba(255,255,255,.18)', boxShadow:'0 10px 30px rgba(0,0,0,.6)',
        maxWidth:'80%', textAlign:'center', transition:'opacity .3s', pointerEvents:'none'});
      document.body.appendChild(s);
    }
    s.style.opacity = texto ? '1' : '0';
    if (texto) s.innerHTML = texto;
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', crear); else crear();
})();
"""

FINAL = """(logo) => {
  const f = document.createElement('div');
  Object.assign(f.style, {position:'fixed', inset:0, zIndex:2147483647, background:'#070707', display:'grid', placeItems:'center',
    color:'#fff', font:'16px system-ui, Segoe UI, sans-serif', textAlign:'center', opacity:0, transition:'opacity .8s'});
  f.innerHTML = `<div><img src="${logo}" style="width:260px;filter:drop-shadow(0 0 30px rgba(255,255,255,.25))">
    <div style="font-size:46px;font-weight:700;margin:18px 0 6px">MailSentry</div>
    <div style="font-size:22px;color:#aaa;margin-bottom:28px">Detector de phishing para empresas</div>
    <div style="font:18px ui-monospace,Consolas,monospace;color:#ff9a5c;line-height:1.9">
      h4nn-sz.github.io/mailsentry<br>github.com/H4nn-sz/mailsentry</div>
    <div style="margin-top:26px;color:#777">Giancarlo Garcia · H4nnlv</div></div>`;
  document.body.appendChild(f); requestAnimationFrame(() => f.style.opacity = 1);
}"""


def subtitulo(pagina, texto: str = "") -> None:
    pagina.evaluate("t => window.__subtitulo && window.__subtitulo(t)", texto)


def mover(pagina, x: float, y: float, pasos: int = 25) -> None:
    pagina.mouse.move(x, y, steps=pasos)


def esperar_servidor() -> None:
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{BASE}/ingresar", timeout=2).close()
            return
        except Exception:
            time.sleep(0.5)
    sys.exit("El servidor de la demo no respondió.")


def credenciales() -> tuple[str, str]:
    texto = (RAIZ / "data" / "demo-credenciales.txt").read_text(encoding="utf-8")
    usuario = re.search(r"usuario:\s*(\S+)", texto).group(1)
    clave = re.search(r"contraseña:\s*(\S+)", texto).group(1)
    return usuario, clave


def grabar(carpeta_video: Path) -> Path:
    usuario, clave = credenciales()
    with sync_playwright() as p:
        navegador = p.chromium.launch()
        contexto = navegador.new_context(viewport={"width": ANCHO, "height": ALTO}, device_scale_factor=1,
                                         record_video_dir=str(carpeta_video),
                                         record_video_size={"width": ANCHO, "height": ALTO}, bypass_csp=True)
        contexto.add_init_script(EXTRAS)
        pg = contexto.new_page()

        # 1. Ingreso
        pg.goto(f"{BASE}/ingresar")
        pg.wait_for_timeout(600)
        subtitulo(pg, "MailSentry · Detector de phishing para empresas")
        pg.wait_for_timeout(1800)
        mover(pg, 800, 560)
        pg.click("#usuario")
        pg.keyboard.type(usuario, delay=90)
        pg.click("#password")
        pg.keyboard.type(clave, delay=45)
        mover(pg, 800, 640)
        pg.click("button[type=submit]")

        # 2. Animación de entrada y panel
        pg.wait_for_url(f"{BASE}/**")
        subtitulo(pg, "")
        pg.wait_for_timeout(3600)
        subtitulo(pg, "Todo el correo de la empresa, vigilado en un solo panel")
        mover(pg, 1150, 75)
        pg.wait_for_timeout(1500)
        pg.click("a.chip:has-text('90 días')")
        pg.wait_for_load_state("networkidle")
        pg.wait_for_timeout(800)
        subtitulo(pg, "<b>129</b> ataques de phishing detectados en 90 días")
        mover(pg, 700, 130, 30)
        pg.wait_for_timeout(2800)

        # 3. Globo
        subtitulo(pg, "¿Desde dónde atacan? País del servidor que envió cada amenaza")
        caja = pg.locator("#globo").bounding_box()
        cx, cy = caja["x"] + caja["width"] / 2, caja["y"] + caja["height"] / 2
        mover(pg, cx, cy, 30)
        pg.mouse.down()
        mover(pg, cx - 260, cy + 20, 60)
        pg.mouse.up()
        pg.wait_for_timeout(2200)
        subtitulo(pg, "Ranking por región y país, sin depender de servicios externos")
        mover(pg, caja["x"] + caja["width"] + 120, cy, 30)
        pg.wait_for_timeout(2800)

        # 4. Gráficos
        subtitulo(pg, "Tipos de ataque, personas y áreas más atacadas, marcas imitadas")
        for _ in range(6):
            pg.mouse.wheel(0, 180)
            pg.wait_for_timeout(260)
        pg.wait_for_timeout(1600)
        for _ in range(4):
            pg.mouse.wheel(0, 200)
            pg.wait_for_timeout(260)
        pg.wait_for_timeout(1800)

        # 5. Detalle de un fraude del CEO
        subtitulo(pg, "Ejemplo: fraude del CEO desde un Gmail")
        pg.goto(f"{BASE}/correos?q=carlos.mendoza.gerencia&veredicto=phishing")
        pg.wait_for_timeout(1200)
        enlace = pg.locator("td.celda-asunto a").first
        mover(pg, *centro(enlace.bounding_box()))
        pg.wait_for_timeout(500)
        enlace.click()
        pg.wait_for_load_state("networkidle")
        subtitulo(pg, "MailSentry explica en español <b>por qué</b> es un fraude")
        pg.wait_for_timeout(3600)
        for _ in range(4):
            pg.mouse.wheel(0, 170)
            pg.wait_for_timeout(300)
        subtitulo(pg, "Remitente, autenticación, país de origen y contenido con enlaces desactivados")
        pg.wait_for_timeout(3000)

        # 6. Análisis de un correo nuevo
        pg.goto(f"{BASE}/analizar")
        subtitulo(pg, "¿Un correo sospechoso? Se pega y se analiza al instante")
        pg.wait_for_timeout(1000)
        pg.click("#fuente")
        pg.fill("#fuente", CORREO_PRUEBA)
        pg.wait_for_timeout(1200)
        boton = pg.locator("button:has-text('Analizar')")
        mover(pg, *centro(boton.bounding_box()))
        boton.click()
        pg.wait_for_load_state("networkidle")
        subtitulo(pg, "Banco falso detectado: <b>robo de credenciales</b>, riesgo crítico")
        pg.wait_for_timeout(4200)

        # 7. Reporte
        pg.goto(f"{BASE}/reporte?periodo=90d")
        subtitulo(pg, "Reporte para gerencia con recomendaciones concretas")
        pg.wait_for_timeout(1800)
        for _ in range(8):
            pg.mouse.wheel(0, 220)
            pg.wait_for_timeout(280)
        pg.wait_for_timeout(1800)

        # 8. Cierre
        subtitulo(pg, "")
        pg.evaluate(FINAL, f"{BASE}/static/img/logo.svg")
        pg.wait_for_timeout(4500)

        ruta_video = Path(pg.video.path())
        contexto.close()
        navegador.close()
        return ruta_video


def centro(caja: dict) -> tuple[float, float]:
    return caja["x"] + caja["width"] / 2, caja["y"] + caja["height"] / 2


def main() -> None:
    if not (RAIZ / "data" / "demo.db").exists():
        sys.exit("Primero genere la demo:  python main.py demo")
    servidor = subprocess.Popen([sys.executable, "main.py", "iniciar", "--demo", "--sin-navegador",
                                 "--sin-vigilancia", "--puerto", str(PUERTO)], cwd=RAIZ,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    temporal = RAIZ / "medios" / "_crudo"
    try:
        esperar_servidor()
        webm = grabar(temporal)
    finally:
        servidor.terminate()
    SALIDA.parent.mkdir(exist_ok=True)
    subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-loglevel", "error", "-i", str(webm),
                    "-c:v", "libx264", "-preset", "slow", "-crf", "22", "-pix_fmt", "yuv420p",
                    "-movflags", "+faststart", str(SALIDA)], check=True)
    shutil.rmtree(temporal, ignore_errors=True)
    print(f"Video: {SALIDA} ({SALIDA.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
