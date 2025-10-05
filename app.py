# app.py - Streamlit web app para la gestión profesional de listas de acceso
# Versión FINAL con Reporte PDF de Auditoría y Trazabilidad SQLite
# CORRECCIÓN: st.experimental_rerun() reemplazado por st.rerun()

import streamlit as st
import ipaddress
import re
import time 
import sqlite3
import pandas as pd 
import io
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

# =================================================================
# 0. CONFIGURACIÓN DE BASE DE DATOS Y TRAZABILIDAD
# =================================================================

DATABASE_NAME = "audit_log.db"

def init_db():
    """Crea la tabla de logs de auditoría si no existe."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            user_id TEXT,
            target_file TEXT NOT NULL,
            ips_revoked INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Inicializar la base de datos al inicio de la aplicación
init_db()

def log_audit_event(user_id, target_file, ips_revoked):
    """Registra una acción de revocación en la base de datos."""
    timestamp = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    action = "Access Revocation Audit" 
    
    cursor.execute("""
        INSERT INTO audit_events (timestamp, action, user_id, target_file, ips_revoked) 
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, action, user_id, target_file, ips_revoked))
    
    conn.commit()
    conn.close()

def load_audit_logs():
    """Carga todos los eventos de auditoría desde la DB."""
    conn = sqlite3.connect(DATABASE_NAME)
    df = pd.read_sql_query("SELECT * FROM audit_events ORDER BY timestamp DESC", conn)
    conn.close()
    
    if 'id' in df.columns:
        df = df.drop(columns=['id'])
        
    return df

# =================================================================
# 1. CONFIGURACIÓN Y TEXTOS (I18n)
# =================================================================

TEXTS = {
    "es": {
        "lang_name": "Español",
        "title": "Herramienta Profesional de Gestión de Listas de Acceso (IPs)",
        "intro": "Esta herramienta garantiza la integridad de sus listas de acceso eliminando IPs obsoletas. Es crucial en entornos sanitarios para mantener la seguridad de los registros de pacientes.",
        "sidebar_title": "⚙️ Configuración",
        "lang_label": "Seleccionar Idioma",
        "quick_guide": "Guía de Uso Rápida",
        "uploader_label": "📁 Cargar Lista de Permitidos (.txt)",
        "delimiter_label": "Delimitador en el archivo cargado",
        "delimiter_options": ["Salto de Línea", "Coma", "Espacio", "Tabulación"],
        "delimiter_values": ["\n", ",", " ", "\t"],
        "input_label": "Lista de IPs a Revocar/Eliminar (una por línea, o separadas por comas)",
        "button_label": "⚙️ Confirmar y Actualizar Archivo",
        "download_label": "⬇️ Descargar Lista Actualizada",
        "success": "✅ ¡Lista de acceso actualizada con éxito! Haga clic para descargar.",
        "warning_audit": "⚠️ Se eliminarán **{removals}** de **{total}** IPs que coinciden. Confirme la acción.",
        "info_no_match": "ℹ️ No se encontraron coincidencias para revocar. El archivo permanecerá sin cambios.",
        "error_validation": "❌ ERROR de Validación: Al menos una de las entradas no es una dirección IP válida. Por favor, corrija los datos y reintente.",
        "error_empty": "❌ ERROR: La lista de IPs a revocar está vacía.",
        "processing": "Procesando listas y realizando auditoría de seguridad...",
        "pdf_download": "📄 Descargar Reporte PDF"
    },
    "en": {
        "lang_name": "English",
        "title": "Professional Access List Management Tool (IPs)",
        "intro": "This tool ensures the integrity of your access lists by removing obsolete IPs. It's crucial in healthcare environments to maintain patient record security.",
        "sidebar_title": "⚙️ Configuration",
        "lang_label": "Select Language",
        "quick_guide": "Quick Usage Guide",
        "uploader_label": "📁 Upload Allowed List (.txt)",
        "delimiter_label": "Delimiter in the uploaded file",
        "delimiter_options": ["New Line", "Comma", "Space", "Tab"],
        "delimiter_values": ["\n", ",", " ", "\t"],
        "input_label": "List of IPs to Revoke/Remove (one per line, or comma-separated)",
        "button_label": "⚙️ Confirm and Update File",
        "download_label": "⬇️ Download Updated List",
        "success": "✅ Access List updated successfully! Click to download.",
        "warning_audit": "⚠️ **{removals}** out of **{total}** matching IPs will be removed. Confirm the action.",
        "info_no_match": "ℹ️ No matches found to revoke. The file will remain unchanged.",
        "error_validation": "❌ Validation ERROR: At least one of the entries is not a valid IP address. Please correct the data and retry.",
        "error_empty": "❌ ERROR: The list of IPs to revoke is empty.",
        "processing": "Processing lists and performing security audit...",
        "pdf_download": "📄 Download PDF Report"
    }
}

# 2. SECCIÓN DE CONFIGURACIÓN (BARRA LATERAL)
with st.sidebar:
    st.title(TEXTS["es"]["sidebar_title"])
    st.markdown("---") 

    lang_selection = st.selectbox(
        TEXTS["es"]["lang_label"], 
        options=list(TEXTS.keys()), 
        format_func=lambda x: TEXTS[x]["lang_name"]
    )
    T = TEXTS[lang_selection]
    
    st.markdown("---") 

    delimiter_map = dict(zip(T["delimiter_options"], T["delimiter_values"]))
    delimiter_name = st.selectbox(
        T["delimiter_label"], 
        options=T["delimiter_options"], 
        index=0 
    )
    delimiter_value = delimiter_map[delimiter_name]

# 3. FUNCIONES DE LÓGICA Y REPORTE
def is_valid_ip(ip_string):
    """Verifica si la cadena de texto es una dirección IPv4 o IPv6 válida."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def get_ips_from_content(content, delimiter_value):
    """Extrae IPs del contenido del archivo basándose en el delimitador."""
    if delimiter_value == "\n":
        raw_ips = content.splitlines()
    else:
        raw_ips = content.split(delimiter_value)
    return {ip.strip() for ip in raw_ips if ip.strip()}

def update_content(content, remove_set, delimiter_value):
    """Realiza la actualización lógica de conjuntos."""
    original_ips = get_ips_from_content(content, delimiter_value)
    ips_to_keep = original_ips - set(remove_set)
    updated_content = "\n".join(sorted(ips_to_keep))
    return updated_content

def generate_pdf_report(original_ips, potential_removals, updated_ips, language):
    """Genera un reporte de auditoría profesional en PDF usando ReportLab."""
    
    if language == 'es':
        R = {"title": "Reporte de Auditoría de Acceso Restringido", "date": "Fecha de Generación:", "section_summary": "1. Resumen Ejecutivo de la Auditoría", "section_details": "2. Detalle de IPs Revocadas", "total_initial": "Total de IPs Iniciales:", "total_removed": "Total de IPs Eliminadas:", "total_final": "Total de IPs Finales:", "ip_list_header": ["IP Revocada", "Estado"], "status_removed": "REVOCADA (Coincidencia)", "status_maintained": "Mantenida", "conclusion": "La herramienta ejecutó la revocación de acceso según lo planificado, garantizando el principio de mínimo privilegio y el cumplimiento normativo."}
    else: 
        R = {"title": "Restricted Access Audit Report", "date": "Generation Date:", "section_summary": "1. Executive Audit Summary", "section_details": "2. Revoked IPs Detail", "total_initial": "Total Initial IPs:", "total_removed": "Total Removed IPs:", "total_final": "Total Final IPs:", "ip_list_header": ["Revoked IP", "Status"], "status_removed": "REVOKED (Match Found)", "status_maintained": "Maintained", "conclusion": "The tool executed access revocation as planned, ensuring the principle of least privilege and regulatory compliance."}

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title=R["title"])
    styles = getSampleStyleSheet()
    Story = []

    # Contenido del PDF (Título, Resumen y Tablas)
    Story.append(Paragraph(f"<b>{R['title']}</b>", styles['Title']))
    Story.append(Spacer(1, 0.5 * A4[1] / 72)) 
    Story.append(Paragraph(f"<b>{R['date']}</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    Story.append(Spacer(1, 0.5 * A4[1] / 72))
    Story.append(Paragraph(f"{R['section_summary']}", styles['h2']))

    summary_data = [
        [R["total_initial"], len(original_ips)],
        [R["total_removed"], len(potential_removals)],
        [R["total_final"], len(updated_ips)]
    ]
    summary_table = Table(summary_data, colWidths=[3*A4[0]/5, A4[0]/5])
    summary_table.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 1, colors.black)]))
    Story.append(summary_table)
    Story.append(Spacer(1, 0.3 * A4[1] / 72))
    Story.append(Paragraph(R["conclusion"], styles['Normal']))
    Story.append(Spacer(1, 0.5 * A4[1] / 72))

    Story.append(Paragraph(R["section_details"], styles['h2']))
    ip_data = [R["ip_list_header"]]
    for ip in sorted(potential_removals):
        ip_data.append([ip, R["status_removed"]])
    if not potential_removals:
         ip_data.append(["N/A", R["status_maintained"]])
         
    detail_table = Table(ip_data, colWidths=[3*A4[0]/5, A4[0]/5])
    detail_table.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 1, colors.black)]))
    Story.append(detail_table)
    
    doc.build(Story)
    buffer.seek(0)
    return buffer

# =================================================================
# 4. STREAMLIT UI PRINCIPAL
# =================================================================

st.title("🛡️ " + T["title"]) 

with st.expander("❓ " + T["quick_guide"]):
    st.markdown(T["intro"])

st.divider() 

# La carga de archivo y el selector de delimitador son independientes, se mantienen en el flujo principal y la barra lateral

col_upload, col_space = st.columns([2, 1])

with col_upload:
    uploaded_file = st.file_uploader(T["uploader_label"], type=["txt"])

# --- Manejo del Estado de Sesión (Inicialización) ---
if 'success' not in st.session_state:
    st.session_state['success'] = False
# ---------------------------------------------------

if uploaded_file is not None:
    # Leer el archivo
    content = uploaded_file.read().decode("utf-8")
    original_ips_loaded = get_ips_from_content(content, delimiter_value)
    
    # 4.2. Entrada de IPs a Revocar
    st.subheader("1. " + T["input_label"])
    remove_input = st.text_area(T["input_label"], height=150, label_visibility="collapsed", key="remove_input") 
    
    st.divider()

    if remove_input:
        
        # Procesamiento y Validación
        raw_remove_list = re.split(r'[,\n\r]+', remove_input)
        remove_list_clean = {item.strip() for item in raw_remove_list if item.strip()}
        
        if not remove_list_clean:
            st.error(T["error_empty"])
            st.session_state['success'] = False
            st.stop()
            
        invalid_ips = [ip for ip in remove_list_clean if not is_valid_ip(ip)]
        
        if invalid_ips:
            st.error(T["error_validation"] + f" IPs no válidas encontradas: {', '.join(invalid_ips)}")
            st.session_state['success'] = False
            st.stop()
            
        # 4.3. Cálculo de Auditoría Previa
        potential_removals = original_ips_loaded.intersection(remove_list_clean)
        
        if potential_removals:
            st.warning(T["warning_audit"].format(removals=len(potential_removals), total=len(original_ips_loaded)))
        else:
            st.info(T["info_no_match"])
        
        # 4.4. Botón de Acción Final
        st.subheader("2. " + T["button_label"])
        
        if st.button(T["button_label"], type="primary"): 
            
            with st.spinner(T["processing"]):
                time.sleep(1.5)
                
                # 1. Ejecutar la actualización de la lista de texto
                updated_content = update_content(content, remove_list_clean, delimiter_value) 
                
                # 2. Generar el reporte PDF de auditoría
                original_ips = get_ips_from_content(content, delimiter_value)
                updated_ips = get_ips_from_content(updated_content, "\n")
                
                pdf_buffer = generate_pdf_report(
                    original_ips=original_ips, 
                    potential_removals=potential_removals, 
                    updated_ips=updated_ips, 
                    language=lang_selection
                )
                
                # 3. TRAZABILIDAD (SQLite Logging)
                user = "admin_default" 
                target = uploaded_file.name
                count = len(potential_removals)
                log_audit_event(user, target, count)
                
            # --- Guardar datos y activar el éxito ---
            st.session_state['updated_content_txt'] = updated_content
            st.session_state['pdf_report'] = pdf_buffer.read()
            st.session_state['file_name_base'] = uploaded_file.name.replace(".txt", "")
            st.session_state['success'] = True
            
            # CORRECCIÓN DEL ERROR: Usar st.rerun()
            st.rerun() 

# 5. MANEJO DE DESCARGAS (Botones persistentes)
if st.session_state['success']:
    st.success(T["success"])
    
    col_download_txt, col_download_pdf = st.columns(2)

    with col_download_txt:
        st.download_button(
            label=T["download_label"] + " (.txt)",
            data=st.session_state['updated_content_txt'],
            file_name=f"{st.session_state['file_name_base']}_updated.txt",
            mime="text/plain"
        )
    
    with col_download_pdf:
        st.download_button(
            label=T["pdf_download"],
            data=st.session_state['pdf_report'],
            file_name=f"{st.session_state['file_name_base']}_Audit_Report.pdf",
            mime="application/pdf"
        )

# =================================================================
# 6. SECCIÓN DE TRAZABILIDAD Y AUDITORÍA (PLAN PRO)
# =================================================================

st.markdown("---")
st.header("📜 Historial de Trazabilidad y Auditoría (Plan Pro)")
st.info("Esta característica de auditoría registra quién, qué y cuándo se realizaron las revocaciones, esencial para el cumplimiento normativo.")

try:
    audit_df = load_audit_logs()
    
    if not audit_df.empty:
        # Renombrar columnas para mejor visualización
        audit_df.columns = ["Fecha/Hora", "Acción", "Usuario", "Archivo Objetivo", "IPs Revocadas"]
        st.dataframe(audit_df, use_container_width=True)
    else:
        st.write("No se han registrado eventos de auditoría.")

except Exception as e:
    st.error(f"Error al cargar los logs de auditoría: {e}. Verifique la integridad del archivo '{DATABASE_NAME}'.")