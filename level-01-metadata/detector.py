from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
import os
from pathlib import Path

class FindDebugFuncsDetector(AbstractDetector):
    """
    Detects functions with 'test' or 'debug' in their name.
    """
    ARGUMENT = 'find-debug-funcs' # The command line flag
    HELP = 'Finds functions that should not be in production'
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://github.com/your-repo/wiki'
    WIKI_TITLE = 'Find Debug Functions Detector'
    WIKI_DESCRIPTION = 'This detector looks for functions that have "debug" or "test"'
    WIKI_EXPLOIT_SCENARIO = 'Having debug or test functions in production can lead to security vulnerabilities.'
    WIKI_RECOMMENDATION = 'Remove any debug or test functions from production code.'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                if any(name in func.name.lower() for name in ['debug', 'test']):
                    info = [f"Suspicious function found: {func.name} in {contract.name}\n"]
                    res = self.generate_result(info) # type: ignore
                    results.append(res)

        return results


if __name__ == "__main__":
    from slither import Slither
    current_dir = Path(__file__).resolve().parent
    slither = Slither(os.path.join(current_dir, "Vulnerable.sol"))
    slither.register_detector(FindDebugFuncsDetector)
    results = slither.run_detectors()
    for detector_results in results:
        for res in detector_results:
            print(f"[!] BUG: {res['description']}")