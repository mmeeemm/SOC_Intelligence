
import torch
from transformers import AutoModelForVision2Seq, AutoProcessor
from qwen_vl_utils import process_vision_info
from PIL import Image
import logging

logger = logging.getLogger(__name__)

class VisionEngine:
    """
    Advanced Visual Forensics Engine for Breach & Leak Analysis.
    Optimized for NVIDIA GPUs with sufficient VRAM.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(VisionEngine, cls).__new__(cls)
            cls._instance.model = None
            cls._instance.processor = None
        return cls._instance

    def load_model(self):
        """
        Loads Qwen2-VL-7B-Instruct with bfloat16 precision.
        """
        if self.model is not None:
            return True

        try:
            model_id = "Qwen/Qwen2-VL-7B-Instruct"
            logger.info(f"Loading Visual Forensics Engine [{model_id}]...")

            # Using bfloat16 for precision
            self.model = AutoModelForVision2Seq.from_pretrained(
                model_id,
                torch_dtype=torch.bfloat16,
                device_map="auto",
                attn_implementation="sdpa",
                trust_remote_code=True
            )

            try:
                logger.info("Compiling Vision Engine graph...")
                self.model = torch.compile(self.model, mode="reduce-overhead")
            except Exception as e:
                logger.warning(f"Vision torch.compile failed: {e}")

            self.processor = AutoProcessor.from_pretrained(model_id, trust_remote_code=True)
            logger.info("Visual Forensics Engine loaded successfully.")
            return True
        except Exception as e:
            logger.error(f"Visual Forensics Engine failed to load: {e}", exc_info=True)
            return False

    def analyze_image(self, image: Image.Image, prompt: str) -> str:
        """
        Executes zero-shot visual forensic analysis.
        """
        if not self.model:
            if not self.load_model():
                return "Error: Visual Forensics Engine (Vision-LLM) is unavailable."

        try:
            messages = [
                {
                    "role": "user",
                    "content": [
                        {"type": "image", "image": image},
                        {"type": "text", "text": prompt},
                    ],
                }
            ]

            text = self.processor.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
            image_inputs, video_inputs = process_vision_info(messages)

            inputs = self.processor(
                text=[text],
                images=image_inputs,
                videos=video_inputs,
                padding=True,
                return_tensors="pt",
            ).to(self.model.device)

            generated_ids = self.model.generate(**inputs, max_new_tokens=2048)
            generated_ids_trimmed = [
                out_ids[len(in_ids) :] for in_ids, out_ids in zip(inputs.input_ids, generated_ids)
            ]

            output_text = self.processor.batch_decode(
                generated_ids_trimmed,
                skip_special_tokens=True,
                clean_up_tokenization_spaces=False
            )

            return output_text[0]
        except Exception as e:
            logger.error(f"Image analysis failed: {e}", exc_info=True)
            return f"Forensic Analysis Error: {str(e)}"

LEAK_FORENSICS_PROMPT = """
# SYSTEM ROLE
You are an autonomous **Digital Forensics Parser** and **Expert Linguist**.
Your input is an image of a leaked artifact (screenshot, document, scan).
Your output must be a professional technical report.

# TASK EXECUTION PROTOCOL
1. **Visual Forensics:** Scan for identities, software versions, IPs, domains, and timestamps.
2. **PII Detection:** Identify any personally identifiable information.
3. **Classification:** Classify according to TLP standards (RED, AMBER, GREEN, CLEAR).
4. **Leak Intelligence:** Analyze if this looks like a valid credential leak or a fake/honeypot.

# OUTPUT STRUCTURE
- **Executive Summary:** High-level overview of the findings.
- **Technical Breakdown:** Specific identifiers and context found in the image.
- **Risk Score:** 1-10.
- **TLP Status:** RED/AMBER/GREEN/CLEAR.
"""
