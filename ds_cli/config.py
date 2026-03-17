from pydantic import BaseModel, Field
import os

class Settings(BaseModel):
    # API configuration for local endpoint (expecting OpenAI compatible API, like Ollama or LM Studio)
    ai_api_key: str = Field(default=os.getenv("AI_API_KEY", "ollama")) # Not heavily used for local but required by client
    ai_api_base: str = Field(default=os.getenv("AI_API_BASE", "http://localhost:11434/v1")) 
    ai_model: str = Field(default=os.getenv("AI_MODEL", "qwen2.5-coder:1.5b"))
    
    # Directory paths
    output_dir: str = Field(default=os.getenv("DS_OUTPUT_DIR", "./ds_reports"))
    config_path: str = Field(default=os.path.expanduser(os.getenv("DS_CONFIG", "~/.ds_config")))

settings = Settings()

# Ensure output directory exists
os.makedirs(settings.output_dir, exist_ok=True)
