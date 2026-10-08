// Comportamiento general del panel.
(function () {
  "use strict";

  // Selects que envían su formulario al cambiar
  document.querySelectorAll("select[data-auto]").forEach(function (s) {
    s.addEventListener("change", function () { s.form.submit(); });
  });

  // Confirmación antes de acciones sensibles
  document.querySelectorAll("form[data-confirmar]").forEach(function (f) {
    f.addEventListener("submit", function (ev) {
      if (!window.confirm(f.dataset.confirmar)) ev.preventDefault();
    });
  });

  // Imprimir (los manejadores en línea están bloqueados por la política de seguridad)
  document.querySelectorAll("[data-imprimir]").forEach(function (b) {
    b.addEventListener("click", function () { window.print(); });
  });

  // Alternar gráfico / tabla
  document.querySelectorAll("[data-alternar]").forEach(function (b) {
    b.addEventListener("click", function () {
      var tarjeta = b.closest(".tarjeta");
      var grafico = tarjeta.querySelector("[data-vista=grafico]");
      var tabla = tarjeta.querySelector("[data-vista=tabla]");
      var verTabla = tabla.classList.contains("oculto");
      tabla.classList.toggle("oculto", !verTabla);
      grafico.classList.toggle("oculto", verTabla);
      b.textContent = verTabla ? "Ver gráfico" : "Ver tabla";
      b.setAttribute("aria-pressed", verTabla ? "true" : "false");
    });
  });

  // Tablero
  var nodoDatos = document.getElementById("datos-panel");
  if (nodoDatos && window.Graficos) {
    var d = JSON.parse(nodoDatos.textContent);
    var G = window.Graficos;
    var enlaceCorreos = function (params) {
      var q = new URLSearchParams(Object.assign({ periodo: d.periodo }, params));
      if (d.buzon) q.set("buzon", d.buzon);
      return "/correos?" + q.toString();
    };

    var pintar = function () {
      var serie = document.getElementById("g-serie");
      if (serie) {
        G.columnasApiladas(serie, {
          titulo: "Amenazas recibidas por " + d.serie.unidad,
          unidad: d.serie.unidad,
          etiquetas: d.serie.etiquetas,
          series: [
            { nombre: "Phishing", color: "--calor", valores: d.serie.phishing },
            { nombre: "Sospechosos", color: "--serie-gris", valores: d.serie.sospechosos }
          ]
        });
      }
      var barras = [
        ["g-categorias", d.categorias.map(function (c) {
          return { etiqueta: c.etiqueta, valor: c.valor, enlace: enlaceCorreos({ veredicto: "amenazas", categoria: c.clave }) };
        })],
        ["g-objetivos", d.objetivos.map(function (o) {
          return { etiqueta: o.nombre, detalle: o.departamento, valor: o.valor,
                   enlace: enlaceCorreos({ veredicto: "amenazas", destinatario: o.email }) };
        })],
        ["g-departamentos", d.departamentos.map(function (o) {
          return { etiqueta: o.etiqueta, valor: o.valor, enlace: enlaceCorreos({ veredicto: "amenazas", departamento: o.etiqueta }) };
        })],
        ["g-marcas", d.marcas.map(function (o) {
          return { etiqueta: o.etiqueta, valor: o.valor, enlace: enlaceCorreos({ veredicto: "amenazas", marca: o.etiqueta }) };
        })]
      ];
      barras.forEach(function (b) {
        var nodo = document.getElementById(b[0]);
        if (nodo) G.barras(nodo, b[1], { vacio: nodo.dataset.vacio });
      });
    };

    var tablas = function () {
      var t = function (id, cols, filas) { var n = document.getElementById(id); if (n) G.tabla(n, cols, filas); };
      t("t-serie", ["Fecha", "Phishing", "Sospechosos"], d.serie.etiquetas.map(function (e, i) {
        return [e, d.serie.phishing[i], d.serie.sospechosos[i]];
      }).filter(function (f) { return f[1] || f[2]; }));
      t("t-categorias", ["Categoría", "Correos"], d.categorias.map(function (c) { return [c.etiqueta, c.valor]; }));
      t("t-objetivos", ["Persona", "Correos"], d.objetivos.map(function (o) { return [o.nombre + " (" + o.departamento + ")", o.valor]; }));
      t("t-departamentos", ["Área", "Correos"], d.departamentos.map(function (o) { return [o.etiqueta, o.valor]; }));
      t("t-marcas", ["Marca", "Correos"], d.marcas.map(function (o) { return [o.etiqueta, o.valor]; }));
    };

    pintar();
    tablas();
    var espera;
    window.addEventListener("resize", function () { clearTimeout(espera); espera = setTimeout(pintar, 120); });

    // El globo ocupa exactamente lo que queda de pantalla debajo de la cabecera y los indicadores
    var tarjetaGlobo = document.querySelector(".globo-tarjeta");
    var ajustarAlto = function () {
      if (!tarjetaGlobo) return;
      var arriba = tarjetaGlobo.getBoundingClientRect().top + window.scrollY;
      document.documentElement.style.setProperty("--alto-superior", Math.round(arriba + 18) + "px");
    };
    ajustarAlto();
    window.addEventListener("resize", ajustarAlto);

    var lienzo = document.getElementById("globo");
    if (lienzo && window.Globo) {
      window.Globo.crear(lienzo, {
        origenes: d.origen.origenes,
        destino: d.origen.ubicacion,
        alSeleccionar: function (o) { window.location = enlaceCorreos({ veredicto: "amenazas", pais: o.codigo }); }
      });
    }
  }
})();
