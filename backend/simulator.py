import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests


DEFAULT_VOICE_ID = "pNInz6obpgDQGcFmaJgB"  # ElevenLabs "Rachel"


@dataclass
class ScenarioStep:
    prompt: str
    options: List[Dict]


@dataclass
class Scenario:
    id: str
    title: str
    script: str
    steps: List[ScenarioStep]


SCENARIOS: Dict[str, Scenario] = {
    "bank_fraud": Scenario(
        id="bank_fraud",
        title="Bank Fraud Alert",
        script=(
            "Hello, this is the Fraud Department from your bank. We detected unusual activity on your card. "
            "Please confirm your identity by sharing the six-digit code we just sent and your card PIN."
        ),
        steps=[
            ScenarioStep(
                prompt="Caller requests the six-digit code and PIN.",
                options=[
                    {
                        "label": "Provide code and PIN",
                        "score": -50,
                        "feedback": "Never share MFA codes or PINs.",
                        "reason": "Once shared, attackers can drain your account.",
                    },
                    {
                        "label": "Ask to call back via bank app",
                        "score": 25,
                        "feedback": "Good—move to a trusted channel.",
                        "reason": "Shifts to an authenticated channel you control.",
                    },
                    {
                        "label": "Hang up immediately",
                        "score": 20,
                        "feedback": "Safe but confirm via official app.",
                        "reason": "Ends social engineering path; verify separately.",
                    },
                ],
            ),
            ScenarioStep(
                prompt="Caller insists and adds time pressure.",
                options=[
                    {
                        "label": "Ignore pressure and call the bank number on card",
                        "score": 30,
                        "feedback": "Correct recovery step.",
                        "reason": "Verifies via official contact, stops pressure tactics.",
                    },
                    {
                        "label": "Stay on call but refuse code",
                        "score": 10,
                        "feedback": "Better to disconnect and verify independently.",
                        "reason": "Reduces risk but leaves attacker engaged.",
                    },
                    {
                        "label": "Provide partial info to 'prove identity'",
                        "score": -30,
                        "feedback": "Even partial data can be abused.",
                        "reason": "Partial data can be combined to bypass checks.",
                    },
                ],
            ),
        ],
    )
}


def get_scenario(scenario_id: str = "bank_fraud") -> Scenario:
    return SCENARIOS.get(scenario_id, list(SCENARIOS.values())[0])


def synthesize_voice(text: str, api_key: Optional[str] = None, voice_id: str = DEFAULT_VOICE_ID) -> Optional[bytes]:
    key = api_key or os.getenv("ELEVENLABS_API_KEY")
    if not key:
        return None
    try:
        resp = requests.post(
            f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}",
            headers={"xi-api-key": key, "Accept": "audio/mpeg"},
            json={"text": text, "model_id": "eleven_multilingual_v2"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.content
    except Exception:
        return None
    return None
