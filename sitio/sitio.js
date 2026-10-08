// Página de MailSentry: globo ilustrativo con orígenes de ejemplo y aparición suave de secciones.
(function () {
  "use strict";
  var lienzo = document.getElementById("globo");
  if (lienzo && window.Globo) {
    // Datos ilustrativos (no son estadísticas reales)
    window.Globo.crear(lienzo, {
      destino: [-12.046, -77.043],
      origenes: [
        { codigo: "PE", pais: "Perú", region: "Sudamérica", lat: -12.05, lon: -77.04, valor: 20, phishing: 18 },
        { codigo: "US", pais: "Estados Unidos", region: "Norteamérica", lat: 39.5, lon: -98.35, valor: 14, phishing: 12 },
        { codigo: "RU", pais: "Rusia", region: "Europa del Este", lat: 55.76, lon: 37.62, valor: 11, phishing: 11 },
        { codigo: "NG", pais: "Nigeria", region: "África", lat: 6.52, lon: 3.38, valor: 8, phishing: 8 },
        { codigo: "BR", pais: "Brasil", region: "Sudamérica", lat: -23.55, lon: -46.63, valor: 7, phishing: 6 },
        { codigo: "MX", pais: "México", region: "Norteamérica", lat: 19.43, lon: -99.13, valor: 6, phishing: 5 },
        { codigo: "NL", pais: "Países Bajos", region: "Europa Occidental", lat: 52.37, lon: 4.9, valor: 4, phishing: 4 },
        { codigo: "CO", pais: "Colombia", region: "Sudamérica", lat: 4.71, lon: -74.07, valor: 3, phishing: 3 }
      ]
    });
  }
  // Las secciones aparecen al hacer scroll
  if ("IntersectionObserver" in window && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    var observador = new IntersectionObserver(function (entradas) {
      entradas.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("visible"); observador.unobserve(e.target); }
      });
    }, { threshold: 0.12 });
    document.querySelectorAll(".seccion").forEach(function (s) { s.classList.add("aparecer"); observador.observe(s); });
  }
})();
