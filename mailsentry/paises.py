"""Países: nombre en español, región y un punto representativo (capital o centro) para el globo."""

from __future__ import annotations

SA, CA, NA = "Sudamérica", "Centroamérica y Caribe", "Norteamérica"
EO, EE, MO = "Europa Occidental", "Europa del Este", "Medio Oriente"
AC, AM, AO, SE = "Asia Central", "Asia Meridional", "Asia Oriental", "Sudeste Asiático"
AF, OC = "África", "Oceanía"

# código ISO 3166-1: (nombre, región, latitud, longitud)
PAISES: dict[str, tuple[str, str, float, float]] = {
    "AR": ("Argentina", SA, -34.60, -58.38), "BO": ("Bolivia", SA, -16.50, -68.15),
    "BR": ("Brasil", SA, -23.55, -46.63), "CL": ("Chile", SA, -33.45, -70.67),
    "CO": ("Colombia", SA, 4.71, -74.07), "EC": ("Ecuador", SA, -0.18, -78.47),
    "GY": ("Guyana", SA, 6.80, -58.16), "PY": ("Paraguay", SA, -25.26, -57.58),
    "PE": ("Perú", SA, -12.05, -77.04), "SR": ("Surinam", SA, 5.85, -55.20),
    "UY": ("Uruguay", SA, -34.90, -56.16), "VE": ("Venezuela", SA, 10.48, -66.90),
    "BZ": ("Belice", CA, 17.25, -88.77), "CR": ("Costa Rica", CA, 9.93, -84.08),
    "SV": ("El Salvador", CA, 13.69, -89.22), "GT": ("Guatemala", CA, 14.63, -90.51),
    "HN": ("Honduras", CA, 14.07, -87.19), "NI": ("Nicaragua", CA, 12.11, -86.24),
    "PA": ("Panamá", CA, 8.98, -79.52), "CU": ("Cuba", CA, 23.11, -82.37),
    "DO": ("República Dominicana", CA, 18.49, -69.93), "HT": ("Haití", CA, 18.59, -72.31),
    "JM": ("Jamaica", CA, 18.02, -76.80), "PR": ("Puerto Rico", CA, 18.47, -66.11),
    "TT": ("Trinidad y Tobago", CA, 10.65, -61.51), "BS": ("Bahamas", CA, 25.05, -77.35),
    "BB": ("Barbados", CA, 13.10, -59.61),
    "US": ("Estados Unidos", NA, 39.50, -98.35), "CA": ("Canadá", NA, 45.42, -75.70),
    "MX": ("México", NA, 19.43, -99.13),
    "GB": ("Reino Unido", EO, 51.51, -0.13), "IE": ("Irlanda", EO, 53.35, -6.26),
    "FR": ("Francia", EO, 48.86, 2.35), "DE": ("Alemania", EO, 50.11, 8.68),
    "NL": ("Países Bajos", EO, 52.37, 4.90), "BE": ("Bélgica", EO, 50.85, 4.35),
    "LU": ("Luxemburgo", EO, 49.61, 6.13), "CH": ("Suiza", EO, 46.95, 7.45),
    "AT": ("Austria", EO, 48.21, 16.37), "ES": ("España", EO, 40.42, -3.70),
    "PT": ("Portugal", EO, 38.72, -9.14), "IT": ("Italia", EO, 41.90, 12.50),
    "MT": ("Malta", EO, 35.90, 14.51), "DK": ("Dinamarca", EO, 55.68, 12.57),
    "NO": ("Noruega", EO, 59.91, 10.75), "SE": ("Suecia", EO, 59.33, 18.07),
    "FI": ("Finlandia", EO, 60.17, 24.94), "IS": ("Islandia", EO, 64.15, -21.94),
    "MC": ("Mónaco", EO, 43.74, 7.42), "LI": ("Liechtenstein", EO, 47.14, 9.52),
    "AD": ("Andorra", EO, 42.51, 1.52), "GR": ("Grecia", EO, 37.98, 23.73),
    "CY": ("Chipre", EO, 35.19, 33.38),
    "RU": ("Rusia", EE, 55.76, 37.62), "UA": ("Ucrania", EE, 50.45, 30.52),
    "BY": ("Bielorrusia", EE, 53.90, 27.56), "PL": ("Polonia", EE, 52.23, 21.01),
    "CZ": ("Chequia", EE, 50.08, 14.44), "SK": ("Eslovaquia", EE, 48.15, 17.11),
    "HU": ("Hungría", EE, 47.50, 19.04), "RO": ("Rumania", EE, 44.43, 26.10),
    "BG": ("Bulgaria", EE, 42.70, 23.32), "MD": ("Moldavia", EE, 47.01, 28.86),
    "LT": ("Lituania", EE, 54.69, 25.28), "LV": ("Letonia", EE, 56.95, 24.11),
    "EE": ("Estonia", EE, 59.44, 24.75), "RS": ("Serbia", EE, 44.79, 20.45),
    "HR": ("Croacia", EE, 45.81, 15.98), "SI": ("Eslovenia", EE, 46.06, 14.51),
    "BA": ("Bosnia y Herzegovina", EE, 43.86, 18.41), "ME": ("Montenegro", EE, 42.44, 19.26),
    "MK": ("Macedonia del Norte", EE, 42.00, 21.43), "AL": ("Albania", EE, 41.33, 19.82),
    "XK": ("Kosovo", EE, 42.66, 21.17),
    "TR": ("Turquía", MO, 41.01, 28.98), "IL": ("Israel", MO, 32.09, 34.78),
    "PS": ("Palestina", MO, 31.90, 35.20), "JO": ("Jordania", MO, 31.95, 35.93),
    "LB": ("Líbano", MO, 33.89, 35.50), "SY": ("Siria", MO, 33.51, 36.29),
    "IQ": ("Irak", MO, 33.31, 44.36), "IR": ("Irán", MO, 35.69, 51.39),
    "SA": ("Arabia Saudita", MO, 24.71, 46.68), "AE": ("Emiratos Árabes Unidos", MO, 25.20, 55.27),
    "QA": ("Catar", MO, 25.29, 51.53), "KW": ("Kuwait", MO, 29.38, 47.99),
    "BH": ("Baréin", MO, 26.23, 50.59), "OM": ("Omán", MO, 23.59, 58.41),
    "YE": ("Yemen", MO, 15.37, 44.19),
    "KZ": ("Kazajistán", AC, 51.17, 71.45), "UZ": ("Uzbekistán", AC, 41.30, 69.24),
    "TM": ("Turkmenistán", AC, 37.96, 58.33), "KG": ("Kirguistán", AC, 42.87, 74.59),
    "TJ": ("Tayikistán", AC, 38.56, 68.79), "AF": ("Afganistán", AC, 34.56, 69.21),
    "AZ": ("Azerbaiyán", AC, 40.41, 49.87), "AM": ("Armenia", AC, 40.18, 44.51),
    "GE": ("Georgia", AC, 41.72, 44.79), "MN": ("Mongolia", AC, 47.89, 106.91),
    "IN": ("India", AM, 28.61, 77.21), "PK": ("Pakistán", AM, 33.68, 73.05),
    "BD": ("Bangladés", AM, 23.81, 90.41), "LK": ("Sri Lanka", AM, 6.93, 79.86),
    "NP": ("Nepal", AM, 27.72, 85.32), "BT": ("Bután", AM, 27.47, 89.64),
    "MV": ("Maldivas", AM, 4.18, 73.51),
    "CN": ("China", AO, 39.90, 116.41), "HK": ("Hong Kong", AO, 22.32, 114.17),
    "MO": ("Macao", AO, 22.20, 113.54), "TW": ("Taiwán", AO, 25.03, 121.57),
    "JP": ("Japón", AO, 35.68, 139.69), "KR": ("Corea del Sur", AO, 37.57, 126.98),
    "KP": ("Corea del Norte", AO, 39.04, 125.76),
    "VN": ("Vietnam", SE, 21.03, 105.85), "TH": ("Tailandia", SE, 13.76, 100.50),
    "MY": ("Malasia", SE, 3.14, 101.69), "SG": ("Singapur", SE, 1.35, 103.82),
    "ID": ("Indonesia", SE, -6.21, 106.85), "PH": ("Filipinas", SE, 14.60, 120.98),
    "KH": ("Camboya", SE, 11.56, 104.92), "LA": ("Laos", SE, 17.98, 102.63),
    "MM": ("Myanmar", SE, 19.76, 96.08), "BN": ("Brunéi", SE, 4.90, 114.94),
    "TL": ("Timor Oriental", SE, -8.56, 125.57),
    "EG": ("Egipto", AF, 30.04, 31.24), "LY": ("Libia", AF, 32.89, 13.19),
    "TN": ("Túnez", AF, 36.81, 10.18), "DZ": ("Argelia", AF, 36.75, 3.06),
    "MA": ("Marruecos", AF, 34.02, -6.83), "SD": ("Sudán", AF, 15.50, 32.56),
    "SS": ("Sudán del Sur", AF, 4.85, 31.58), "ET": ("Etiopía", AF, 9.03, 38.74),
    "KE": ("Kenia", AF, -1.29, 36.82), "UG": ("Uganda", AF, 0.35, 32.58),
    "TZ": ("Tanzania", AF, -6.16, 35.75), "RW": ("Ruanda", AF, -1.94, 30.06),
    "BI": ("Burundi", AF, -3.43, 29.93), "SO": ("Somalia", AF, 2.05, 45.32),
    "DJ": ("Yibuti", AF, 11.59, 43.15), "ER": ("Eritrea", AF, 15.32, 38.93),
    "NG": ("Nigeria", AF, 6.52, 3.38), "GH": ("Ghana", AF, 5.60, -0.19),
    "CI": ("Costa de Marfil", AF, 5.36, -4.01), "SN": ("Senegal", AF, 14.72, -17.47),
    "ML": ("Malí", AF, 12.64, -8.00), "BF": ("Burkina Faso", AF, 12.37, -1.52),
    "NE": ("Níger", AF, 13.51, 2.11), "TD": ("Chad", AF, 12.13, 15.06),
    "CM": ("Camerún", AF, 3.85, 11.50), "CF": ("República Centroafricana", AF, 4.39, 18.56),
    "GA": ("Gabón", AF, 0.42, 9.47), "CG": ("Congo", AF, -4.26, 15.24),
    "CD": ("R. D. del Congo", AF, -4.44, 15.27), "AO": ("Angola", AF, -8.84, 13.23),
    "ZM": ("Zambia", AF, -15.39, 28.32), "ZW": ("Zimbabue", AF, -17.83, 31.05),
    "MZ": ("Mozambique", AF, -25.97, 32.57), "MW": ("Malaui", AF, -13.96, 33.79),
    "MG": ("Madagascar", AF, -18.88, 47.51), "NA": ("Namibia", AF, -22.56, 17.08),
    "BW": ("Botsuana", AF, -24.63, 25.92), "ZA": ("Sudáfrica", AF, -26.20, 28.05),
    "LS": ("Lesoto", AF, -29.31, 27.48), "SZ": ("Esuatini", AF, -26.31, 31.14),
    "BJ": ("Benín", AF, 6.50, 2.60), "TG": ("Togo", AF, 6.13, 1.22),
    "SL": ("Sierra Leona", AF, 8.48, -13.23), "LR": ("Liberia", AF, 6.30, -10.80),
    "GN": ("Guinea", AF, 9.64, -13.58), "GW": ("Guinea-Bisáu", AF, 11.86, -15.60),
    "GM": ("Gambia", AF, 13.45, -16.58), "MR": ("Mauritania", AF, 18.08, -15.98),
    "CV": ("Cabo Verde", AF, 14.93, -23.51), "MU": ("Mauricio", AF, -20.16, 57.50),
    "SC": ("Seychelles", AF, -4.62, 55.45),
    "AU": ("Australia", OC, -33.87, 151.21), "NZ": ("Nueva Zelanda", OC, -41.29, 174.78),
    "PG": ("Papúa Nueva Guinea", OC, -9.44, 147.18), "FJ": ("Fiyi", OC, -18.14, 178.44),
    "NC": ("Nueva Caledonia", OC, -22.26, 166.46), "PF": ("Polinesia Francesa", OC, -17.53, -149.57),
    "WS": ("Samoa", OC, -13.83, -171.76), "TO": ("Tonga", OC, -21.14, -175.20),
    "VU": ("Vanuatu", OC, -17.73, 168.32), "SB": ("Islas Salomón", OC, -9.43, 159.95),
}


def nombre(codigo: str | None) -> str:
    if not codigo:
        return "Desconocido"
    return PAISES.get(codigo.upper(), (codigo.upper(),))[0]


def region(codigo: str | None) -> str:
    if not codigo or codigo.upper() not in PAISES:
        return "Otras"
    return PAISES[codigo.upper()][1]


def coordenadas(codigo: str | None) -> tuple[float, float] | None:
    datos = PAISES.get((codigo or "").upper())
    return (datos[2], datos[3]) if datos else None
