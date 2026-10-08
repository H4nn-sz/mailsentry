// Animación de entrada: al terminar (o al saltarla) retira la capa y "abre" el panel en cascada.
(function () {
  "use strict";
  var intro = document.getElementById("intro");
  if (!intro) return;
  var DURACION = 3000;
  var terminado = false;

  function terminar(rapido) {
    if (terminado) return;
    terminado = true;
    if (rapido) intro.classList.add("intro-salto");
    document.body.classList.remove("con-intro");
    document.body.classList.add("revelar");
    setTimeout(function () { intro.remove(); }, rapido ? 350 : 50);
    // Seguro: si la pestaña estaba en segundo plano el navegador pausa las animaciones;
    // al quitar la clase el panel queda visible igual, pase lo que pase con la animación.
    setTimeout(function () { document.body.classList.remove("revelar"); }, 1600);
    document.removeEventListener("keydown", saltar);
    window.dispatchEvent(new Event("resize")); // el globo y los gráficos recalculan su tamaño
  }

  function saltar() { terminar(true); }

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    intro.remove();
    document.body.classList.remove("con-intro");
    return;
  }
  intro.addEventListener("click", saltar);
  document.addEventListener("keydown", saltar);
  setTimeout(function () { terminar(false); }, DURACION);
})();
