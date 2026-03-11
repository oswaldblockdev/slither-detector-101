from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import LowLevelCall
from slither.analyses.data_dependency.data_dependency import is_dependent
from pathlib import Path
import os

class TaintAnalysisDetector(AbstractDetector):
    ARGUMENT = 'check-taint'
    HELP = 'Flag external calls to user-controlled destination addresses'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://github.com/your-repo/wiki/level9'
    WIKI_TITLE = 'Arbitrary Call Destination'
    WIKI_DESCRIPTION = 'This detector identifies low-level calls where the destination address is dependent on a function parameter.'
    WIKI_EXPLOIT_SCENARIO = 'If an attacker can control the destination of a call, they can force the contract to interact with malicious addresses.'
    WIKI_RECOMMENDATION = 'Do not allow user-supplied addresses to be used as call targets without validation.'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                # 1. Look for Low Level Calls (The Sink)
                for node in func.nodes:
                    for ir in node.irs:
                        if isinstance(ir, LowLevelCall):
                            dest = ir.destination
                            
                            # 2. Iterate through function parameters (The Sources)
                            for param in func.parameters:
                                # 3. CORRECT API: Use the is_dependent utility function
                                # This checks if 'dest' (variable) depends on 'param' (source)
                                if is_dependent(dest, param, contract):
                                    info = [
                                        f"Taint Warning: {func.name} in {contract.name} performs a call to an address controlled by '{param.name}'!\n",
                                        node
                                    ]
                                    res = self.generate_result(info) # type: ignore
                                    results.append(res)
                                    break 
        return results

if __name__ == "__main__":
    from slither import Slither
    current_dir = Path(__file__).resolve().parent
    vulnerable_sol = os.path.join(current_dir, "Vulnerable.sol")
    
    if os.path.exists(vulnerable_sol):
        print(f"🕵️ Analyzing Data Flow in: {vulnerable_sol}")
        # Note: Some data dependency analyses require Slither to be initialized 
        # with specific configurations or to run certain printers first.
        slither = Slither(vulnerable_sol)
        slither.register_detector(TaintAnalysisDetector)
        results = slither.run_detectors()
        
        for detector_results in results:
            for res in detector_results:
                print(f"[!] BUG: {res['description']}")