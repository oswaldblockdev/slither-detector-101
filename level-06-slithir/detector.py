from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall
from pathlib import Path
import os

class SelfDestructDetector(AbstractDetector):
    ARGUMENT = 'find-selfdestruct'
    HELP = 'Detect selfdestruct usage via SOLIDITY_CALL IR'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://github.com/your-repo/wiki/level6'
    WIKI_TITLE = 'Selfdestruct Found'
    WIKI_DESCRIPTION = 'This detector identifies selfdestruct by looking for SOLIDITY_CALL IRs that target the selfdestruct built-in function.'
    WIKI_EXPLOIT_SCENARIO = 'Selfdestruct can lead to contract deletion and loss of funds, often used in malicious rugpulls.'
    WIKI_RECOMMENDATION = 'Do not use selfdestruct; use the Pausable pattern if you need to disable a contract.'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                for node in func.nodes:
                    for ir in node.irs:
                        if isinstance(ir, SolidityCall):
                            if "selfdestruct" in ir.function.name or "suicide" in ir.function.name:
                                info = [
                                    f"Critical: {contract.name} calls '{ir.function.name}' in {func.name}!\n",
                                    node                                ]
                                
                                res = self.generate_result(info) # type: ignore
                                results.append(res)
                                break 
        return results

if __name__ == "__main__":
    from slither import Slither
    current_dir = Path(__file__).resolve().parent
    vulnerable_sol = os.path.join(current_dir, "Vulnerable.sol")
    
    if not os.path.exists(vulnerable_sol):
        print(f"❌ Error: {vulnerable_sol} not found.")
    else:
        print(f"🔍 Deep Diving into SOLIDITY_CALL IRs for: {vulnerable_sol}")
        slither = Slither(vulnerable_sol)
        slither.register_detector(SelfDestructDetector)
        results = slither.run_detectors()
        
        found = False
        for detector_results in results:
            for res in detector_results:
                print(f"[!] BUG: {res['description']}")
                found = True
        
        if not found:
            print("✅ No selfdestruct SOLIDITY_CALLs detected.")