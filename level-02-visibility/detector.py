from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from pathlib import Path
import os

class VisibilityAuthDetector(AbstractDetector):
    ARGUMENT = 'check-auth'
    HELP = 'Flag public state-changing functions without authorization modifiers'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'https://github.com/your-repo/wiki/level2'
    WIKI_TITLE = 'Visibility and Authorization'
    WIKI_DESCRIPTION = 'This detector identifies public functions that modify state but lack common authorization checks.'
    WIKI_EXPLOIT_SCENARIO = 'An attacker could call a public function that changes state without any restrictions, leading to potential exploits.'
    WIKI_RECOMMENDATION = 'Ensure that all public functions that modify state have appropriate authorization checks, such as onlyOwner or role-based modifiers.'

    def _detect(self):
        # detect conditions:
        # 1. check visibility
        # 2. change state
        # 3. check for common auth modifiers (onlyOwner, onlyRole, authorized)
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                if func.is_constructor or func.visibility in ['internal', 'private']:
                    continue

                if len(func.state_variables_written) > 0:
                    modifiers = [m.name.lower() for m in func.modifiers]
                    has_auth = any(auth in m for m in modifiers for auth in ['owner', 'role', 'auth'])

                    if not has_auth:
                        info = [f"Critical: {func.name} in {contract.name} changes state but has no auth modifier!\n"]
                        res = self.generate_result(info) # type: ignore
                        results.append(res)

        return results

if __name__ == "__main__":
    from slither import Slither
    current_dir = Path(__file__).resolve().parent
    slither = Slither(os.path.join(current_dir, "Vulnerable.sol"))
    slither.register_detector(VisibilityAuthDetector)
    results = slither.run_detectors()
    for detector_results in results:
        for res in detector_results:
            print(f"[!] BUG: {res['description']}")