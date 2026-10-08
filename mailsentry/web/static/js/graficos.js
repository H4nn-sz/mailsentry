// Gráficos del panel en SVG/HTML, sin dependencias externas (funciona sin internet).
window.Graficos = (function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var fmt = new Intl.NumberFormat("es-PE");
  var tip = null;

  function css(nombre) {
    return getComputedStyle(document.documentElement).getPropertyValue(nombre).trim();
  }

  function el(tag, attrs, padre) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (padre) padre.appendChild(e);
    return e;
  }

  function escapar(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function tooltip() {
    if (!tip) {
      tip = document.createElement("div");
      tip.className = "tooltip";
      tip.setAttribute("role", "status");
      document.body.appendChild(tip);
    }
    return tip;
  }

  function mostrar(html, x, y) {
    var t = tooltip();
    t.innerHTML = html;
    t.classList.add("visible");
    var r = t.getBoundingClientRect();
    var izq = x + 14, arriba = y - r.height - 12;
    if (izq + r.width > window.innerWidth - 8) izq = x - r.width - 14;
    if (arriba < 8) arriba = y + 16;
    t.style.left = Math.max(8, izq) + "px";
    t.style.top = arriba + "px";
  }

  function ocultar() { if (tip) tip.classList.remove("visible"); }

  // Escala "redonda" para enteros: 0, 2, 4, 6...
  function escala(maximo) {
    if (maximo <= 0) return { max: 4, paso: 1 };
    var bruto = maximo / 4;
    var mag = Math.pow(10, Math.floor(Math.log10(bruto)));
    var norm = bruto / mag;
    var paso = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag;
    paso = Math.max(1, Math.round(paso));
    return { max: Math.ceil(maximo / paso) * paso, paso: paso };
  }

  function rutaColumna(x, y, w, h, radio) {
    var r = Math.min(radio, w / 2, h);
    var abajo = y + h;
    return "M" + x + "," + abajo + "V" + (y + r) + "Q" + x + "," + y + " " + (x + r) + "," + y +
      "H" + (x + w - r) + "Q" + (x + w) + "," + y + " " + (x + w) + "," + (y + r) + "V" + abajo + "Z";
  }

  // Columnas apiladas en el tiempo. series: [{nombre, color (variable CSS), valores}]
  function columnasApiladas(contenedor, datos) {
    contenedor.innerHTML = "";
    var n = datos.etiquetas.length;
    if (!n) return;
    var ancho = contenedor.clientWidth || 600;
    var altoPlot = 220, bandaX = 26, izq = 34, der = 6, arriba = 8;
    var plotW = ancho - izq - der;
    var totales = datos.etiquetas.map(function (_, i) {
      return datos.series.reduce(function (s, serie) { return s + serie.valores[i]; }, 0);
    });
    var esc = escala(Math.max.apply(null, totales));
    var svg = el("svg", { viewBox: "0 0 " + ancho + " " + (altoPlot + bandaX + arriba), role: "img",
      "aria-label": datos.titulo || "Gráfico de columnas" }, contenedor);
    svg.style.height = (altoPlot + bandaX + arriba) + "px";
    var y = function (v) { return arriba + altoPlot - (v / esc.max) * altoPlot; };

    for (var t = 0; t <= esc.max; t += esc.paso) {
      el("line", { x1: izq, x2: ancho - der, y1: y(t), y2: y(t), stroke: t === 0 ? css("--eje") : css("--grid"),
        "stroke-width": 1, "shape-rendering": "crispEdges" }, svg);
      var etq = el("text", { x: izq - 8, y: y(t) + 4, "text-anchor": "end" }, svg);
      etq.textContent = fmt.format(t);
    }

    var banda = plotW / n;
    var anchoBarra = Math.max(2, Math.min(24, banda * 0.7));
    var cadaCuanto = Math.ceil(n / Math.max(2, Math.floor(plotW / 64)));

    datos.etiquetas.forEach(function (etiqueta, i) {
      var x = izq + i * banda + (banda - anchoBarra) / 2;
      var acumulado = 0;
      var visibles = datos.series.filter(function (s) { return s.valores[i] > 0; });
      visibles.forEach(function (serie, k) {
        var v = serie.valores[i];
        var alto = (v / esc.max) * altoPlot;
        var tope = y(acumulado + v);
        var esUltimo = k === visibles.length - 1;
        var altoVisible = esUltimo ? alto : Math.max(1, alto - 2); // 2 px de separación entre segmentos
        var desplazamiento = esUltimo ? 0 : 2;
        if (esUltimo) {
          el("path", { d: rutaColumna(x, tope, anchoBarra, alto, 4), fill: css(serie.color) }, svg);
        } else {
          el("rect", { x: x, y: tope + desplazamiento, width: anchoBarra, height: altoVisible, fill: css(serie.color) }, svg);
        }
        acumulado += v;
      });
      if (i % cadaCuanto === 0) {
        var tx = el("text", { x: izq + i * banda + banda / 2, y: arriba + altoPlot + 17, "text-anchor": "middle" }, svg);
        tx.textContent = etiqueta;
      }
      var zona = el("rect", { x: izq + i * banda, y: arriba, width: banda, height: altoPlot, fill: "transparent" }, svg);
      zona.addEventListener("mousemove", function (ev) {
        var filas = datos.series.map(function (s) {
          return '<div class="fila"><span><i style="background:' + css(s.color) + '"></i>' + escapar(s.nombre) +
            "</span><b>" + fmt.format(s.valores[i]) + "</b></div>";
        }).join("");
        var prefijo = datos.unidad && datos.unidad !== "día" ? (datos.unidad === "semana" ? "Semana del " : "") : "";
        mostrar("<b>" + escapar(prefijo + etiqueta) + "</b>" + filas +
          '<div class="fila"><span>Total</span><b>' + fmt.format(totales[i]) + "</b></div>", ev.clientX, ev.clientY);
        zona.setAttribute("fill", css("--grid"));
        zona.setAttribute("fill-opacity", "0.45");
      });
      zona.addEventListener("mouseleave", function () { ocultar(); zona.setAttribute("fill", "transparent"); });
      if (datos.enlace) {
        zona.style.cursor = "pointer";
        zona.addEventListener("click", function () { window.location = datos.enlace(i); });
      }
    });
  }

  // Barras horizontales ordenadas. items: [{etiqueta, detalle?, valor, enlace?}]
  function barras(contenedor, items, opciones) {
    opciones = opciones || {};
    contenedor.innerHTML = "";
    if (!items.length) {
      contenedor.innerHTML = '<div class="vacio">' + escapar(opciones.vacio || "Sin datos en este periodo") + "</div>";
      return;
    }
    var maximo = Math.max.apply(null, items.map(function (i) { return i.valor; })) || 1;
    var total = items.reduce(function (s, i) { return s + i.valor; }, 0);
    var lista = document.createElement("div");
    lista.className = "barras";
    items.forEach(function (item) {
      var fila = document.createElement(item.enlace ? "a" : "div");
      fila.className = "barra-fila";
      if (item.enlace) fila.href = item.enlace;
      fila.innerHTML = '<span class="barra-etq" title="' + escapar(item.etiqueta) + '">' + escapar(item.etiqueta) +
        (item.detalle ? "<small>" + escapar(item.detalle) + "</small>" : "") + "</span>" +
        '<span class="barra-valor">' + fmt.format(item.valor) + "</span>" +
        '<span class="barra-pista"><span class="barra-fill" style="width:' + (item.valor / maximo * 100).toFixed(1) +
        '%"></span></span>';
      fila.addEventListener("mousemove", function (ev) {
        mostrar("<b>" + escapar(item.etiqueta) + "</b>" + fmt.format(item.valor) + " correos · " +
          Math.round(item.valor * 100 / total) + "% del total", ev.clientX, ev.clientY);
      });
      fila.addEventListener("mouseleave", ocultar);
      lista.appendChild(fila);
    });
    contenedor.appendChild(lista);
  }

  // Tabla equivalente a un gráfico (accesible y para lectura exacta)
  function tabla(contenedor, columnas, filas) {
    var html = '<div class="tabla-env"><table><thead><tr>' + columnas.map(function (c, i) {
      return "<th" + (i ? ' class="num"' : "") + ">" + escapar(c) + "</th>";
    }).join("") + "</tr></thead><tbody>" + filas.map(function (f) {
      return "<tr>" + f.map(function (v, i) {
        return "<td" + (i ? ' class="num"' : "") + ">" + escapar(typeof v === "number" ? fmt.format(v) : v) + "</td>";
      }).join("") + "</tr>";
    }).join("") + "</tbody></table></div>";
    contenedor.innerHTML = filas.length ? html : '<div class="vacio">Sin datos en este periodo</div>';
  }

  return { columnasApiladas: columnasApiladas, barras: barras, tabla: tabla, mostrar: mostrar, ocultar: ocultar };
})();
