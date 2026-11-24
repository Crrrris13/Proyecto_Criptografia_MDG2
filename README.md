# Proyecto RSA – MM2015 Matemática Discreta 1

**Integrantes (Grupo No. 2):**
* Marco Prera – 25468
* Cristopher Chávez – 25199

## Requisitos
* **Python:** 3.10 o superior (con Tcl/Tk 8.6 o superior).
* **Dependencias:** Ninguna librería externa requerida (utiliza únicamente la biblioteca estándar de Python, incluyendo `tkinter`).
  * **Linux (Ubuntu/Debian):** Si `tkinter` no viene preinstalado, ejecutar `sudo apt install python3-tk`.
  * **macOS:** Evitar el Python integrado del sistema (`/usr/bin/python3`, que utiliza Tcl/Tk 8.5 obsoleto) y ejecutar con una instalación moderna de Python (por ejemplo, `python3.14 main.py` o `python3.12 main.py`).

## Estructura del Proyecto
* `main.py`: Interfaz gráfica de usuario (Tkinter) con pestañas para encriptar y desencriptar.
* `rsa_core.py`: Validación de parámetros, codificación en bloques ASCII de 2 caracteres y flujo de cifrado/descifrado.
* `rsa_math.py`: Implementación de primalidad, algoritmo de Euclides (`mcd`), inverso modular y exponenciación modular.
* `DEMOSTRACION_VISUAL.mp4`: Video demostrativo del funcionamiento del programa.

## Ejecución
Desde la carpeta raíz del proyecto, ejecutar:
```bash
python3 main.py
```
*(En Windows puede ejecutarse como `python main.py`; en macOS usar la versión instalada, como `python3.14 main.py`).*
