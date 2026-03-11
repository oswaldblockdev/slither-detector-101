from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall, LowLevelCall, HighLevelCall
from pathlib import Path
import os

class GuardRailDetector(AbstractDetector):
    ARGUMENT = 'check-guards'
    HELP = 'Flag external calls not preceded by an authorization/state require()'
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH
    
    WIKI = 'https://github.com/your-repo/wiki/level7'
    WIKI_TITLE = 'Missing Guard Rail'
    WIKI_DESCRIPTION = 'External calls should generally be protected by require() or assert() statements to ensure valid state or authorization.'
    WIKI_EXPLOIT_SCENARIO = 'A function allows any user to trigger an external call to a sensitive contract because no require(msg.sender == authorized) check exists.'
    WIKI_RECOMMENDATION = 'Add a require() check before performing external calls.'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                # 1. Find the node(s) where the external call happens
                call_nodes = [n for n in func.nodes if any(isinstance(ir, (LowLevelCall, HighLevelCall)) for ir in n.irs)]
                
                for c_node in call_nodes:
                    # 2. Look for "Pre-Guards"
                    
                    has_pre_guard = False
                    # func.nodes_ordered_by_id gives us a topological-like order
                    for node in func.nodes:
                        # We only care about nodes that come before the call in the execution flow
                        if node.node_id < c_node.node_id:
                            for ir in node.irs:
                                if isinstance(ir, SolidityCall) and any(guard in ir.function.name for guard in ["require", "assert"]):
                                    # This is a guard that happens BEFORE the call
                                    has_pre_guard = True
                                    break
                        if has_pre_guard:
                            break

                    if not has_pre_guard:
                        info = [
                            f"Guard Warning: {func.name} in {contract.name} performs an external call at Node {c_node.node_id} without a PREceding require() check!\n",
                            c_node
                        ]
                        res = self.generate_result(info) # type: ignore
                        results.append(res)
        return results

if __name__ == "__main__":
    from slither import Slither
    current_dir = Path(__file__).resolve().parent
    vulnerable_sol = os.path.join(current_dir, "Vulnerable.sol")
    
    if os.path.exists(vulnerable_sol):
        slither = Slither(vulnerable_sol)
        slither.register_detector(GuardRailDetector)
        results = slither.run_detectors()
        
        for detector_results in results:
            for res in detector_results:
                print(f"[!] BUG: {res['description']}")