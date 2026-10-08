// Globo de puntos con el origen de los ataques (canvas 2D, proyección ortográfica, sin dependencias).
window.Globo = (function () {
  "use strict";
  var RAD = Math.PI / 180;

  function css(nombre) {
    return getComputedStyle(document.documentElement).getPropertyValue(nombre).trim();
  }

  function vector(lat, lon) {
    var la = lat * RAD, lo = lon * RAD;
    return [Math.cos(la) * Math.cos(lo), Math.cos(la) * Math.sin(lo), Math.sin(la)];
  }

  function puntosTierra() {
    var T = window.MAILSENTRY_TIERRA, salida = [];
    if (!T) return new Float32Array(0);
    T.filas.forEach(function (f) {
      var lat = -90 + (f[0] + 0.5) * T.paso, n = f[1];
      for (var k = 2; k < f.length; k += 2) {
        for (var j = f[k]; j < f[k] + f[k + 1]; j++) {
          var v = vector(lat, -180 + (j + 0.5) * 360 / n);
          salida.push(v[0], v[1], v[2]);
        }
      }
    });
    return new Float32Array(salida);
  }

  function slerp(a, b, t) {
    var dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    var om = Math.acos(dot);
    if (om < 1e-6) return a.slice();
    var s = Math.sin(om), wa = Math.sin((1 - t) * om) / s, wb = Math.sin(t * om) / s;
    return [a[0] * wa + b[0] * wb, a[1] * wa + b[1] * wb, a[2] * wa + b[2] * wb];
  }

  function crear(lienzo, opciones) {
    var ctx = lienzo.getContext("2d");
    var tierra = puntosTierra();
    var reducido = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var origenes = (opciones.origenes || []).filter(function (o) { return o.lat !== null; });
    var maximo = Math.max.apply(null, origenes.map(function (o) { return o.valor; }).concat([1]));
    var destino = opciones.destino ? vector(opciones.destino[0], opciones.destino[1]) : null;
    var focos = origenes.map(function (o, i) {
      var v = vector(o.lat, o.lon);
      var angulo = destino ? Math.acos(Math.max(-1, Math.min(1, v[0] * destino[0] + v[1] * destino[1] + v[2] * destino[2]))) : 0;
      return { dato: o, v: v, alto: 0.06 + 0.30 * Math.sqrt(o.valor / maximo), angulo: angulo, fase: (i * 0.37) % 1 };
    });

    // Vista inicial: centrada cerca de la empresa (para MYPEs peruanas, Sudamérica al frente)
    var rotLon = opciones.destino ? opciones.destino[1] + 25 : 0;
    var rotLat = opciones.destino ? Math.max(-25, Math.min(25, opciones.destino[0] * 0.6)) : 10;
    var arrastrando = null, ultimaInteraccion = 0, tiempo = 0, visible = true;
    var ancho = 0, alto = 0, dpr = 1, R = 0, cx = 0, cy = 0;
    var dibujados = [];
    var cubetas = [];
    for (var b = 0; b < 8; b++) cubetas.push({ n: 0, xs: new Float32Array(tierra.length / 3) , ys: new Float32Array(tierra.length / 3) });

    function medir() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      ancho = lienzo.clientWidth;
      alto = lienzo.clientHeight;
      lienzo.width = Math.round(ancho * dpr);
      lienzo.height = Math.round(alto * dpr);
      // Zona libre: debajo del título superpuesto (arriba) y encima de la leyenda (abajo)
      var superior = ancho < 720 ? 12 : 92, inferior = ancho < 720 ? 12 : 40;
      var libre = alto - superior - inferior;
      R = Math.max(60, Math.min(ancho * 0.42, libre * 0.44));
      cx = ancho / 2;
      cy = superior + libre / 2;
    }

    function proyectar(x, y, z, cl, sl, cp, sp) {
      var x1 = x * cl + y * sl, y1 = -x * sl + y * cl;
      var prof = x1 * cp + z * sp, z2 = -x1 * sp + z * cp;
      return [cx + R * y1, cy - R * z2, prof, Math.sqrt(y1 * y1 + z2 * z2)];
    }

    function dibujar() {
      var cl = Math.cos(rotLon * RAD), sl = Math.sin(rotLon * RAD);
      var cp = Math.cos(rotLat * RAD), sp = Math.sin(rotLat * RAD);
      var calor = css("--calor") || "#e5672b";
      var brillo = css("--calor-brillo") || "#ff9a5c";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, ancho, alto);

      // Halo y cuerpo de la esfera
      var halo = ctx.createRadialGradient(cx, cy, R * 0.98, cx, cy, R * 1.18);
      halo.addColorStop(0, "rgba(255,255,255,0.10)");
      halo.addColorStop(1, "rgba(255,255,255,0)");
      ctx.fillStyle = halo;
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.18, 0, Math.PI * 2); ctx.fill();
      var cuerpo = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.1, cx, cy, R);
      cuerpo.addColorStop(0, "#1d1d1d");
      cuerpo.addColorStop(1, "#060606");
      ctx.fillStyle = cuerpo;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = "rgba(255,255,255,0.14)";
      ctx.lineWidth = 1;
      ctx.stroke();

      // Retícula (paralelos y meridianos cada 30°)
      ctx.strokeStyle = "rgba(255,255,255,0.07)";
      ctx.beginPath();
      var p, previo;
      for (var lat = -60; lat <= 60; lat += 30) {
        previo = null;
        for (var lon = -180; lon <= 180; lon += 4) {
          var v = vector(lat, lon);
          p = proyectar(v[0], v[1], v[2], cl, sl, cp, sp);
          if (p[2] > 0 && previo) { ctx.moveTo(previo[0], previo[1]); ctx.lineTo(p[0], p[1]); }
          previo = p[2] > 0 ? p : null;
        }
      }
      for (var lo = -180; lo < 180; lo += 30) {
        previo = null;
        for (var la = -88; la <= 88; la += 4) {
          var w = vector(la, lo);
          p = proyectar(w[0], w[1], w[2], cl, sl, cp, sp);
          if (p[2] > 0 && previo) { ctx.moveTo(previo[0], previo[1]); ctx.lineTo(p[0], p[1]); }
          previo = p[2] > 0 ? p : null;
        }
      }
      ctx.stroke();

      // Tierra: puntos agrupados por brillo (más tenues hacia el borde, efecto de volumen)
      cubetas.forEach(function (c) { c.n = 0; });
      for (var i = 0; i < tierra.length; i += 3) {
        var x = tierra[i], y = tierra[i + 1], z = tierra[i + 2];
        var x1 = x * cl + y * sl;
        var prof = x1 * cp + z * sp;
        if (prof <= 0.02) continue;
        var y1 = -x * sl + y * cl, z2 = -x1 * sp + z * cp;
        var c = cubetas[Math.min(7, Math.floor(prof * 8))];
        c.xs[c.n] = cx + R * y1; c.ys[c.n] = cy - R * z2; c.n++;
      }
      var tam = Math.max(1.2, R / 210);
      cubetas.forEach(function (c, k) {
        ctx.fillStyle = "rgba(225,225,225," + (0.16 + k * 0.095).toFixed(3) + ")";
        for (var j = 0; j < c.n; j++) ctx.fillRect(c.xs[j] - tam / 2, c.ys[j] - tam / 2, tam, tam);
      });

      // Arcos de ataque hacia la empresa, con un pulso que viaja por cada uno
      dibujados = [];
      if (destino) {
        focos.slice(0, 14).forEach(function (f) {
          var elev = 0.04 + 0.16 * (f.angulo / Math.PI);
          var puntos = [];
          for (var s = 0; s <= 48; s++) {
            var t = s / 48, q = slerp(f.v, destino, t), k2 = 1 + elev * Math.sin(Math.PI * t);
            var pr = proyectar(q[0] * k2, q[1] * k2, q[2] * k2, cl, sl, cp, sp);
            pr.push(pr[2] > 0 || pr[3] > 1);
            puntos.push(pr);
          }
          ctx.lineWidth = 1.2;
          for (var s2 = 1; s2 < puntos.length; s2++) {
            var a = puntos[s2 - 1], bb = puntos[s2];
            if (!a[4] || !bb[4]) continue;
            ctx.strokeStyle = "rgba(229,103,43," + (0.12 + 0.45 * (s2 / puntos.length)).toFixed(3) + ")";
            ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(bb[0], bb[1]); ctx.stroke();
          }
          if (!reducido) {
            var idx = Math.floor(((tiempo * 0.00025 + f.fase) % 1) * 48);
            var pulso = puntos[idx];
            if (pulso && pulso[4]) {
              ctx.fillStyle = brillo;
              ctx.beginPath(); ctx.arc(pulso[0], pulso[1], 2.2, 0, Math.PI * 2); ctx.fill();
            }
          }
        });
      }

      // Focos: barras radiales cuya altura crece con la cantidad de ataques
      focos.forEach(function (f) {
        var base = proyectar(f.v[0], f.v[1], f.v[2], cl, sl, cp, sp);
        if (base[2] <= 0.02) return;
        var k3 = 1 + f.alto;
        var punta = proyectar(f.v[0] * k3, f.v[1] * k3, f.v[2] * k3, cl, sl, cp, sp);
        var alfa = Math.min(1, 0.35 + base[2]);
        ctx.globalAlpha = alfa;
        ctx.strokeStyle = calor;
        ctx.lineWidth = Math.max(2, R / 110);
        ctx.lineCap = "round";
        ctx.beginPath(); ctx.moveTo(base[0], base[1]); ctx.lineTo(punta[0], punta[1]); ctx.stroke();
        ctx.fillStyle = brillo;
        ctx.beginPath(); ctx.arc(punta[0], punta[1], Math.max(2.4, R / 90), 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = calor;
        ctx.beginPath(); ctx.ellipse(base[0], base[1], 3.2, 3.2 * Math.max(0.3, base[2]), 0, 0, Math.PI * 2); ctx.fill();
        ctx.globalAlpha = 1;
        dibujados.push({ f: f, x: punta[0], y: punta[1], bx: base[0], by: base[1], prof: base[2] });
      });

      // Etiquetas de los 4 países principales visibles (texto en tinta neutra, nunca en el color del dato)
      ctx.font = "600 11.5px system-ui, -apple-system, 'Segoe UI', sans-serif";
      ctx.textBaseline = "middle";
      dibujados.slice().sort(function (a, b2) { return b2.f.dato.valor - a.f.dato.valor; }).slice(0, 4)
        .forEach(function (d) {
          if (d.prof < 0.25) return;
          var texto = d.f.dato.pais + " · " + d.f.dato.valor;
          var tx = d.x + 9, anchoTexto = ctx.measureText(texto).width;
          if (tx + anchoTexto > ancho - 6) tx = d.x - 9 - anchoTexto;
          ctx.fillStyle = "rgba(10,10,10,0.72)";
          ctx.fillRect(tx - 5, d.y - 10, anchoTexto + 10, 20);
          ctx.fillStyle = css("--texto") || "#f5f5f5";
          ctx.fillText(texto, tx, d.y);
        });

      // Empresa: anillo blanco pulsante
      if (destino) {
        var e = proyectar(destino[0], destino[1], destino[2], cl, sl, cp, sp);
        if (e[2] > 0) {
          var pulsoE = reducido ? 0.5 : (tiempo * 0.001) % 1;
          ctx.strokeStyle = "rgba(255,255,255," + (0.9 - pulsoE * 0.8).toFixed(3) + ")";
          ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(e[0], e[1], 4 + pulsoE * 12, 0, Math.PI * 2); ctx.stroke();
          ctx.fillStyle = "#ffffff";
          ctx.beginPath(); ctx.arc(e[0], e[1], 3.2, 0, Math.PI * 2); ctx.fill();
        }
      }
    }

    function cuadro(ahora) {
      if (!visible) return;
      var dt = Math.min(64, ahora - (tiempo || ahora));
      tiempo = ahora;
      if (!reducido && !arrastrando && ahora - ultimaInteraccion > 2500) rotLon -= dt * 0.006;
      dibujar();
      if (!reducido) requestAnimationFrame(cuadro);
    }

    function buscar(ev) {
      var r = lienzo.getBoundingClientRect(), px = ev.clientX - r.left, py = ev.clientY - r.top;
      var mejor = null, distancia = 18;
      dibujados.forEach(function (d) {
        var dd = Math.min(Math.hypot(d.x - px, d.y - py), Math.hypot(d.bx - px, d.by - py));
        if (dd < distancia) { distancia = dd; mejor = d; }
      });
      return mejor;
    }

    lienzo.addEventListener("pointerdown", function (ev) {
      arrastrando = { x: ev.clientX, y: ev.clientY, lon: rotLon, lat: rotLat, movio: false };
      lienzo.setPointerCapture(ev.pointerId);
    });
    lienzo.addEventListener("pointermove", function (ev) {
      if (arrastrando) {
        var dx = ev.clientX - arrastrando.x, dy = ev.clientY - arrastrando.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) arrastrando.movio = true;
        rotLon = arrastrando.lon - dx * 0.35;
        rotLat = Math.max(-70, Math.min(70, arrastrando.lat + dy * 0.35));
        ultimaInteraccion = performance.now();
        if (reducido) dibujar();
        if (window.Graficos) window.Graficos.ocultar();
        return;
      }
      var d = buscar(ev);
      lienzo.style.cursor = d ? "pointer" : "grab";
      if (d && window.Graficos) {
        var o = d.f.dato;
        window.Graficos.mostrar("<b>" + o.pais + "</b>" + '<div class="fila"><span>Región</span><b>' + o.region +
          '</b></div><div class="fila"><span>Amenazas</span><b>' + o.valor + '</b></div><div class="fila"><span>Phishing</span><b>' +
          o.phishing + "</b></div>", ev.clientX, ev.clientY);
      } else if (window.Graficos) {
        window.Graficos.ocultar();
      }
    });
    lienzo.addEventListener("pointerup", function (ev) {
      var clic = arrastrando && !arrastrando.movio;
      arrastrando = null;
      ultimaInteraccion = performance.now();
      if (clic && opciones.alSeleccionar) {
        var d = buscar(ev);
        if (d) opciones.alSeleccionar(d.f.dato);
      }
    });
    lienzo.addEventListener("pointerleave", function () { if (window.Graficos) window.Graficos.ocultar(); });

    medir();
    if (window.ResizeObserver) new ResizeObserver(function () { medir(); dibujar(); }).observe(lienzo);
    if (window.IntersectionObserver) {
      new IntersectionObserver(function (entradas) {
        var antes = visible;
        visible = entradas[0].isIntersecting;
        if (visible && !antes && !reducido) requestAnimationFrame(cuadro);
      }).observe(lienzo);
    }
    if (reducido) dibujar(); else requestAnimationFrame(cuadro);
    return { redibujar: dibujar };
  }

  return { crear: crear };
})();
