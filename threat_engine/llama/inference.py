import subprocess
from pathlib import Path

RUNNER = Path.home() / "executorch/cmake-out/examples/models/llama/llama_main"

MODEL = Path(
    "/mnt/c/Users/laksh/.cache/huggingface/hub/"
    "models--executorch-community--Llama-3.2-1B-Instruct-ET/"
    "snapshots/a890af65db35c8a68836d9cb1921b4b7223420a4/"
    "Llama-3.2-1B-Instruct.pte"
)

TOKENIZER = MODEL.parent / "tokenizer.model"


def run_llama(prompt):
    """Run Llama using the native ExecuTorch runner."""

    result = subprocess.run(
        [
            str(RUNNER),
            f"--model_path={MODEL}",
            f"--tokenizer_path={TOKENIZER}",
            "--num_bos=1",
            f"--prompt={prompt}",
            "--max_new_tokens=80",
            "--temperature=0",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Llama runner failed:\n{result.stderr}\n{result.stdout}"
        )

    lines = [
        line for line in result.stdout.splitlines()
        if not line.startswith("PyTorchObserver ")
    ]

    output = "\n".join(lines).strip()

    # Remove the echoed prompt if it appears at the beginning.
    if output.startswith(prompt):
        output = output[len(prompt):].strip()

    return output
