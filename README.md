# VirusTotal MCP Server

Servidor MCP para VirusTotal.

## Uso
1. Instala dependencias: `pip install -r requirements.txt`
2. Configura `.env`
3. Ejecuta: `python server.py`

## Configuración en Claude Desktop

Para integrar este servidor en Claude, edita tu archivo de configuración:
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

Añade la siguiente configuración:

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "python",
      "args": ["<RUTA_ABSOLUTA_AL_ARCHIVO>/server.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "tu_clave_api_aqui"
      }
    }
  }
}
```