"""Capa 2: identidad del remitente (suplantación de directivos, marcas y dominios parecidos)."""

from __future__ import annotations

import re

from ..parser import CorreoParseado
from ..util import normalizar
from .contexto import Contexto
from .datos import CORREO_GRATUITO, PALABRAS_CORPORATIVAS, TLD_SOSPECHOSOS
from .dominios import (
    buscar_parecido,
    dominio_de_marca,
    dominio_registrable,
    limpiar_host,
    marcas_en_texto,
    parecido_a_marca,
    tld,
)
from .modelos import Indicador

RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
BEC = {"bec": 0.7, "fraude_pagos": 0.3}


def analizar(correo: CorreoParseado, ctx: Contexto) -> list[Indicador]:
    ind: list[Indicador] = []
    email = correo.remitente_email
    dominio = limpiar_host(correo.remitente_dominio)
    nombre = correo.remitente_nombre
    nombre_n = normalizar(nombre)
    propio = ctx.es_propio(dominio)
    gratuito = dominio in CORREO_GRATUITO
    auth = correo.autenticacion
    auth_falla = auth.get("dmarc") == "fail" or auth.get("spf") in ("fail", "softfail")

    if not email:
        ind.append(Indicador("REMITENTE_VACIO", "Remitente ausente o mal formado",
                             "La cabecera From no contiene una dirección válida.", 15, "media"))
        return ind

    # Listas administradas por la empresa
    if ctx.bloqueado(email):
        ind.append(Indicador("LISTA_BLOQUEADA", "Remitente en lista de bloqueo",
                             f"{email} está en la lista de remitentes bloqueados de la empresa.", 100, "critica",
                             {"otro": 1.0}))
    elif ctx.permitido(email) and not auth_falla:
        ind.append(Indicador("LISTA_PERMITIDA", "Remitente de confianza",
                             f"{email} está en la lista de remitentes permitidos y su autenticación es válida.",
                             -40, "info"))

    # Suplantación del dominio propio de la empresa
    if propio:
        if auth_falla:
            ind.append(Indicador("SUPLANTACION_DOMINIO_PROPIO", "Suplantación del dominio de la empresa",
                                 f"Dice venir de {dominio} (su propio dominio) pero no pasó la autenticación: "
                                 "alguien externo está falsificando su dirección.", 45, "critica", BEC))
        if correo.responder_a and not ctx.es_propio(correo.responder_a.rsplit("@", 1)[-1]):
            ind.append(Indicador("PROPIO_RESPONDER_EXTERNO", "Correo interno que responde hacia afuera",
                                 f"Viene de su dominio pero las respuestas irán a {correo.responder_a}.",
                                 25, "alta", BEC))
    else:
        parecido = buscar_parecido(dominio, ctx.dominios_propios)
        if parecido:
            protegido, tecnica = parecido
            ind.append(Indicador("DOMINIO_SIMILAR_PROPIO", "Dominio que imita al de la empresa",
                                 f"{dominio} imita a {protegido}: {tecnica}.", 50, "critica",
                                 {"bec": 0.6, "fraude_pagos": 0.4}))
        else:
            marca = parecido_a_marca(dominio)
            if marca:
                nombre_marca, legitimo, tecnica = marca
                ind.append(Indicador("DOMINIO_SIMILAR_MARCA", f"Dominio que imita a {nombre_marca}",
                                     f"{dominio} imita a {legitimo}: {tecnica}.", 35, "alta",
                                     {"suplantacion_marca": 0.6, "credenciales": 0.4}, marca=nombre_marca))
            elif dominio not in CORREO_GRATUITO:
                # Imitación de un proveedor o cliente habitual (fraude de facturas)
                conocido = buscar_parecido(dominio, ctx.dominios_conocidos - CORREO_GRATUITO, estricto=True)
                if conocido:
                    ind.append(Indicador("DOMINIO_SIMILAR_CONOCIDO", "Dominio que imita a un contacto habitual",
                                         f"{dominio} imita a {conocido[0]}, de quien la empresa recibe correos "
                                         f"legítimos: {conocido[1]}.", 40, "critica",
                                         {"fraude_pagos": 0.6, "bec": 0.4}))

    if "xn--" in dominio:
        ind.append(Indicador("REMITENTE_PUNYCODE", "Dominio con caracteres internacionales",
                             f"{dominio} usa codificación punycode, técnica común para imitar dominios.", 20, "alta",
                             {"suplantacion_marca": 0.5, "credenciales": 0.5}))
    if tld(dominio) in TLD_SOSPECHOSOS:
        ind.append(Indicador("REMITENTE_TLD", "Extensión de dominio de alto riesgo",
                             f"La extensión .{tld(dominio)} es muy usada en campañas de phishing por ser barata.",
                             10, "baja", {"credenciales": 0.5, "suplantacion_marca": 0.5}))

    # Nombre visible con una dirección distinta a la real
    en_nombre = RE_EMAIL.search(nombre)
    if en_nombre and en_nombre.group(0).lower() != email:
        ind.append(Indicador("NOMBRE_CON_OTRO_EMAIL", "El nombre visible muestra otra dirección",
                             f"Se muestra «{en_nombre.group(0)}» pero el correo real es {email}.", 25, "alta",
                             {"suplantacion_marca": 0.5, "bec": 0.5}))

    # Suplantación de directivos y empleados (fraude del CEO)
    if not propio:
        vip = ctx.buscar_persona(nombre, ctx.vips)
        if vip:
            extra = " desde un correo gratuito" if gratuito else ""
            # Solo el nombre no basta para afirmar fraude (el directivo puede usar su correo personal):
            # queda en revisión, y se vuelve crítico si además pide dinero o un favor (COMBO_BEC).
            ind.append(Indicador("SUPLANTACION_DIRECTIVO", "Usa el nombre de un directivo desde otra dirección",
                                 f"Usa el nombre de {vip.nombre}{f' ({vip.cargo})' if vip.cargo else ''}{extra}, "
                                 f"pero escribe desde {email} y no desde su correo {vip.email}. "
                                 "Verifique por teléfono antes de actuar.",
                                 45 if gratuito else 40, "alta", BEC))
        else:
            empleado = ctx.buscar_persona(nombre, ctx.empleados)
            if empleado:
                ind.append(Indicador("SUPLANTACION_EMPLEADO", "Usa el nombre de un empleado",
                                     f"El remitente se presenta como {empleado.nombre} pero escribe desde {email} "
                                     f"(su correo es {empleado.email}).", 25, "alta", BEC))

    # Marca en el nombre visible enviada desde un dominio ajeno a la marca
    if not propio:
        for marca in marcas_en_texto(nombre_n, es_remitente=True):
            if not dominio_de_marca(dominio, marca):
                origen = "un correo gratuito" if gratuito else dominio
                ind.append(Indicador("MARCA_EN_NOMBRE", f"Se hace pasar por {marca}",
                                     f"El remitente se llama «{nombre}» pero envía desde {origen}, "
                                     f"que no pertenece a {marca}.", 40 if gratuito else 30, "alta",
                                     {"suplantacion_marca": 0.7, "credenciales": 0.3}, marca=marca))
                break

    if gratuito and any(re.search(rf"\b{p}\b", nombre_n) for p in PALABRAS_CORPORATIVAS):
        ind.append(Indicador("GRATUITO_CORPORATIVO", "Cargo corporativo desde correo gratuito",
                             f"«{nombre}» escribe desde {dominio}: las áreas de una empresa no usan correos gratuitos.",
                             15, "media", BEC))

    # Responder-A hacia otro dominio
    if correo.responder_a and "@" in correo.responder_a:
        dom_resp = correo.responder_a.rsplit("@", 1)[1]
        if dominio_registrable(dom_resp) != dominio_registrable(dominio) and not ctx.es_propio(dom_resp):
            gratis = dom_resp in CORREO_GRATUITO
            ind.append(Indicador("RESPONDER_A_DISTINTO", "Las respuestas van a otra dirección",
                                 f"Si responde, su mensaje irá a {correo.responder_a}"
                                 f"{' (correo gratuito)' if gratis else ''} y no a {email}.",
                                 25 if gratis else 15, "alta" if gratis else "media", BEC))

    if not propio and dominio and dominio_registrable(dominio) not in ctx.dominios_conocidos and dominio not in CORREO_GRATUITO:
        ind.append(Indicador("REMITENTE_NUEVO", "Primer contacto con este dominio",
                             f"Nunca antes se recibió un correo legítimo de {dominio_registrable(dominio)}.", 3, "baja"))
    return ind
