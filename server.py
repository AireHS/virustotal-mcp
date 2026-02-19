import os
import base64
import httpx
from fastmcp import FastMCP
from typing import Optional, Dict, Any

# Configuración inicial
mcp = FastMCP("VirusTotal MCP")
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

if not API_KEY:
    # Intentar cargar desde .env si no está en el entorno (opcional para desarrollo local sin docker)
    try:
        from dotenv import load_dotenv
        load_dotenv()
        API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    except ImportError:
        pass

if not API_KEY:
    raise ValueError(
        "Error: La variable de entorno VIRUSTOTAL_API_KEY no está configurada. "
        "Verifica que tu archivo .env tenga el formato correcto (CLAVE=VALOR) o define la variable en tu sistema."
    )

# --- Helpers y Lógica de Formateo ---

def _get_headers() -> Dict[str, str]:
    """Devuelve los headers necesarios para la autenticación."""
    return {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }

def _url_to_id(url: str) -> str:
    """
    Convierte una URL en un identificador de VirusTotal (Base64 URL-safe sin padding).
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def _format_stats(stats: Dict[str, int]) -> str:
    """Formatea las estadísticas de análisis."""
    return ", ".join([f"{k}: {v}" for k, v in stats.items()])

def _format_response(data: Dict[str, Any], resource_type: str) -> str:
    """
    Procesa el JSON crudo de VT y devuelve un resumen legible para el LLM.
    """
    try:
        if resource_type == "search":
            # La búsqueda devuelve una lista de items
            items = data.get("data", [])
            if not items:
                return "No se encontraron resultados para la búsqueda."
            
            summary = [f"Resultados encontrados: {len(items)} (mostrando top 5)"]
            for item in items[:5]:
                attrs = item.get("attributes", {})
                item_id = item.get("id", "N/A")
                item_type = item.get("type", "unknown")
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                summary.append(f"- [{item_type}] ID: {item_id} | Malicious: {malicious}")
            return "\n".join(summary)

        # Para reportes individuales (file, ip, domain, url)
        attrs = data.get("data", {}).get("attributes", {})
        if not attrs:
            return "No se pudieron extraer atributos del reporte."

        stats = attrs.get("last_analysis_stats", {})
        reputation = attrs.get("reputation", 0)
        tags = attrs.get("tags", [])
        
        # Información específica según el tipo
        names = attrs.get("meaningful_name") or attrs.get("type_description") or "N/A"
        
        report = (
            f"--- Reporte de VirusTotal ({resource_type}) ---\n"
            f"Reputación: {reputation}\n"
            f"Estadísticas de detección: {_format_stats(stats)}\n"
            f"Etiquetas: {', '.join(tags) if tags else 'Ninguna'}\n"
            f"Descripción/Nombre: {names}\n"
            f"Enlace al reporte: https://www.virustotal.com/gui/{resource_type}/{data.get('data', {}).get('id')}"
        )
        return report

    except Exception as e:
        return f"Error al formatear la respuesta: {str(e)}"

async def _make_request(endpoint: str) -> str:
    """
    Realiza la petición HTTP asíncrona a VirusTotal y maneja errores comunes.
    """
    url = f"{BASE_URL}{endpoint}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=_get_headers())
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "Recurso no encontrado en VirusTotal (404)."}
            elif response.status_code == 401:
                return {"error": "Error de autenticación. Verifica tu API Key."}
            elif response.status_code == 429:
                return {"error": "Límite de cuota de API excedido."}
            else:
                return {"error": f"Error inesperado de la API: {response.status_code} - {response.text}"}
        except httpx.RequestError as e:
            return {"error": f"Error de conexión: {str(e)}"}

# --- Definición de Herramientas MCP ---

@mcp.tool()
async def get_file_report(file_hash: str) -> str:
    """
    Consulta el análisis de un archivo utilizando su hash (MD5, SHA-1 o SHA-256).
    
    Args:
        file_hash: El hash del archivo a consultar.
    """
    data = await _make_request(f"/files/{file_hash}")
    if "error" in data:
        return data["error"]
    return _format_response(data, "file")

@mcp.tool()
async def get_ip_report(ip: str) -> str:
    """
    Consulta la reputación y el análisis de una dirección IP.
    
    Args:
        ip: La dirección IP a consultar (ej. 8.8.8.8).
    """
    data = await _make_request(f"/ip_addresses/{ip}")
    if "error" in data:
        return data["error"]
    return _format_response(data, "ip-address")

@mcp.tool()
async def get_domain_report(domain: str) -> str:
    """
    Consulta la reputación y el análisis de un dominio.
    
    Args:
        domain: El nombre de dominio a consultar (ej. google.com).
    """
    data = await _make_request(f"/domains/{domain}")
    if "error" in data:
        return data["error"]
    return _format_response(data, "domain")

@mcp.tool()
async def get_url_report(url: str) -> str:
    """
    Consulta el último análisis disponible de una URL específica.
    Nota: Esto consulta un análisis ya existente, no solicita un escaneo nuevo.
    
    Args:
        url: La URL completa a consultar (ej. https://www.ejemplo.com).
    """
    # VT requiere que la URL sea codificada en base64 para usarla como ID
    url_id = _url_to_id(url)
    data = await _make_request(f"/urls/{url_id}")
    if "error" in data:
        return f"{data['error']} (Es posible que la URL no haya sido analizada antes)"
    return _format_response(data, "url")

@mcp.tool()
async def search_virustotal(query: str) -> str:
    """
    Realiza una búsqueda general en la base de datos de VirusTotal.
    Puede buscar dominios, IPs, hashes o URLs.
    
    Args:
        query: El término de búsqueda.
    """
    # La búsqueda requiere codificación de parámetros URL estándar
    data = await _make_request(f"/search?query={query}")
    if "error" in data:
        return data["error"]
    return _format_response(data, "search")

if __name__ == "__main__":
    # Ejecuta el servidor MCP
    try:
        mcp.run()
    except KeyboardInterrupt:
        pass
