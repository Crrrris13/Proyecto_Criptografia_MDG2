import streamlit as st

from rsa_core import ErrorRSA, parsear_entero, encriptar, desencriptar


def entre_comillas(texto):
    return f'"{texto}"'


def caracteres_visibles(texto):
    return " ".join(f"'{ch}'" for ch in texto)


def init_state():
    defaults = {
        "p": "367",
        "q": "373",
        "e": "17",
        "mensaje_enc": "RSA",
        "res_enc": None,
        "err_enc": "",
        "copia_enc": "",
        "cifrado_dec": "",
        "L_dec": "",
        "p_dec": "367",
        "q_dec": "373",
        "e_dec": "17",
        "res_dec": None,
        "err_dec": "",
        "copia_dec": "",
        "pestana": "Encriptar",
    }
    for clave, valor in defaults.items():
        if clave not in st.session_state:
            st.session_state[clave] = valor


def leer_parametros(p_str, q_str, e_str):
    p = parsear_entero(p_str, "p")
    q = parsear_entero(q_str, "q")
    e = parsear_entero(e_str, "e")
    return p, q, e


def fila_parametros(clave_p, clave_q, clave_e, sufijo):
    st.markdown("**Parámetros:**")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.session_state[clave_p] = st.text_input(
            "p:", value=st.session_state[clave_p], key=f"p_{sufijo}"
        )
    with c2:
        st.session_state[clave_q] = st.text_input(
            "q:", value=st.session_state[clave_q], key=f"q_{sufijo}"
        )
    with c3:
        st.session_state[clave_e] = st.text_input(
            "e:", value=st.session_state[clave_e], key=f"e_{sufijo}"
        )


def mostrar_campos_resultado(titulo, pares, sufijo):
    with st.container(border=True):
        st.markdown(f"**{titulo}**")
        for idx, (etiqueta, valor) in enumerate(pares):
            c_etq, c_val = st.columns([1.4, 3.6])
            with c_etq:
                st.markdown(etiqueta)
            with c_val:
                st.text_input(
                    etiqueta,
                    value=valor,
                    disabled=True,
                    label_visibility="collapsed",
                    key=f"out_{sufijo}_{idx}",
                )


def mostrar_tabla_proceso(filas_dict):
    with st.container(border=True):
        st.markdown("**Detalle del proceso**")
        st.dataframe(filas_dict, use_container_width=True, hide_index=True)


def panel_encriptar():
    with st.container(border=True):
        st.session_state["mensaje_enc"] = st.text_area(
            "Mensaje M:",
            value=st.session_state["mensaje_enc"],
            height=85,
            key="txt_m_enc",
        )
        fila_parametros("p", "q", "e", "enc")

    b1, b2, b3, _ = st.columns([1.2, 1.2, 2.0, 2.6])
    with b1:
        clic_enc = st.button("Encriptar", use_container_width=True, key="btn_encriptar")
    with b2:
        clic_copiar = st.button("Copiar C", use_container_width=True, key="btn_copiar_c")
    with b3:
        clic_enviar = st.button(
            "Enviar a Desencriptar", use_container_width=True, key="btn_enviar"
        )

    if clic_enc:
        st.session_state["err_enc"] = ""
        st.session_state["copia_enc"] = ""
        try:
            p, q, e = leer_parametros(
                st.session_state["p"],
                st.session_state["q"],
                st.session_state["e"],
            )
            mensaje = st.session_state["mensaje_enc"]
            st.session_state["res_enc"] = encriptar(mensaje, p, q, e)
        except ErrorRSA as ex:
            st.session_state["res_enc"] = None
            st.session_state["err_enc"] = str(ex)
        except Exception as ex:
            st.session_state["res_enc"] = None
            st.session_state["err_enc"] = f"Error inesperado: {ex}"

    if clic_copiar:
        if st.session_state["res_enc"]:
            st.session_state["copia_enc"] = st.session_state["res_enc"].cifrado

    if clic_enviar:
        r = st.session_state["res_enc"]
        if not r:
            st.session_state["err_enc"] = "Primero encripta un mensaje válido."
        else:
            st.session_state["cifrado_dec"] = r.cifrado
            st.session_state["L_dec"] = str(r.L)
            st.session_state["p_dec"] = str(r.p)
            st.session_state["q_dec"] = str(r.q)
            st.session_state["e_dec"] = str(r.e)
            st.session_state["err_dec"] = ""
            st.session_state["pestana"] = "Desencriptar"
            st.rerun()

    if st.session_state["err_enc"]:
        st.markdown(f":red[⚠ {st.session_state['err_enc']}]")

    if st.session_state["copia_enc"]:
        st.code(st.session_state["copia_enc"], language=None)

    r = st.session_state["res_enc"]
    if r is not None:
        relleno_texto = (
            "Sí: se agregó 1 espacio al final (L es impar)"
            if r.relleno
            else "No (L es par)"
        )
        mostrar_campos_resultado(
            "Resultado",
            [
                ("Cifrado C:", r.cifrado),
                ("Longitud L:", str(r.L)),
                ("Llave pública (e, n):", f"({r.e}, {r.n})"),
                ("n = p·q:", str(r.n)),
                ("φ = (p−1)(q−1):", str(r.phi)),
                ("Relleno:", relleno_texto),
                ("Mensaje con relleno:", entre_comillas(r.mensaje_relleno)),
            ],
            "enc",
        )
        filas_dict = [
            {
                "Bloque": f.indice,
                "Caracteres": caracteres_visibles(f.caracteres),
                "ASCII (3 dígitos)": f"{f.codigos[0]:03d} {f.codigos[1]:03d}",
                "m (antes de cifrar)": f"{f.m:06d}",
                "c = m^e mod n": f.c,
                "c (6 dígitos)": f"{f.c:06d}",
            }
            for f in r.filas
        ]
        mostrar_tabla_proceso(filas_dict)


def panel_desencriptar():
    with st.container(border=True):
        st.session_state["cifrado_dec"] = st.text_area(
            "Cifrado C:",
            value=st.session_state["cifrado_dec"],
            height=85,
            key="txt_c_dec",
        )
        st.session_state["L_dec"] = st.text_input(
            "Longitud L:",
            value=st.session_state["L_dec"],
            key="txt_l_dec",
        )
        fila_parametros("p_dec", "q_dec", "e_dec", "dec")

    b1, b2, _ = st.columns([1.3, 1.2, 4.5])
    with b1:
        clic_dec = st.button(
            "Desencriptar", use_container_width=True, key="btn_desencriptar"
        )
    with b2:
        clic_copiar = st.button("Copiar M", use_container_width=True, key="btn_copiar_m")

    if clic_dec:
        st.session_state["err_dec"] = ""
        st.session_state["copia_dec"] = ""
        try:
            p, q, e = leer_parametros(
                st.session_state["p_dec"],
                st.session_state["q_dec"],
                st.session_state["e_dec"],
            )
            st.session_state["res_dec"] = desencriptar(
                st.session_state["cifrado_dec"],
                st.session_state["L_dec"],
                p,
                q,
                e,
            )
        except ErrorRSA as ex:
            st.session_state["res_dec"] = None
            st.session_state["err_dec"] = str(ex)
        except Exception as ex:
            st.session_state["res_dec"] = None
            st.session_state["err_dec"] = f"Error inesperado: {ex}"

    if clic_copiar:
        if st.session_state["res_dec"]:
            st.session_state["copia_dec"] = st.session_state["res_dec"].mensaje

    if st.session_state["err_dec"]:
        st.markdown(f":red[⚠ {st.session_state['err_dec']}]")

    if st.session_state["copia_dec"]:
        st.code(st.session_state["copia_dec"], language=None)

    r = st.session_state["res_dec"]
    if r is not None:
        relleno_texto = (
            "Sí: se retiró exactamente el último carácter (espacio de relleno)"
            if r.relleno
            else "No (L es par): no se retiró ningún carácter"
        )
        mostrar_campos_resultado(
            "Resultado",
            [
                ("Mensaje M:", r.mensaje),
                ("M entre comillas:", entre_comillas(r.mensaje)),
                ("Exponente privado d:", str(r.d)),
                ("Llave privada (d, n):", f"({r.d}, {r.n})"),
                ("n = p·q:", str(r.n)),
                ("φ = (p−1)(q−1):", str(r.phi)),
                ("Longitud L:", str(r.L)),
                ("Relleno:", relleno_texto),
                ("Texto recuperado (con relleno):", entre_comillas(r.texto_recuperado)),
            ],
            "dec",
        )
        filas_dict = [
            {
                "Bloque": f.indice,
                "c (6 dígitos)": f"{f.c:06d}",
                "m = c^d mod n": f.m,
                "m (6 dígitos)": f"{f.m:06d}",
                "ASCII": f"{f.codigos[0]:03d} {f.codigos[1]:03d}",
                "Caracteres": caracteres_visibles(f.caracteres),
            }
            for f in r.filas
        ]
        mostrar_tabla_proceso(filas_dict)


def main():
    st.set_page_config(page_title="RSA – MM2015 Matemática Discreta 1", layout="wide")
    init_state()
    st.subheader("RSA – MM2015 Matemática Discreta 1")

    seleccion = st.radio(
        "Sección",
        ["Encriptar", "Desencriptar"],
        index=0 if st.session_state["pestana"] == "Encriptar" else 1,
        horizontal=True,
        label_visibility="collapsed",
        key="radio_pestana",
    )
    if seleccion != st.session_state["pestana"]:
        st.session_state["pestana"] = seleccion
        st.rerun()

    if st.session_state["pestana"] == "Encriptar":
        panel_encriptar()
    else:
        panel_desencriptar()


if __name__ == "__main__":
    main()