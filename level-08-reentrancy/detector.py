from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import LowLevelCall, HighLevelCall
from pathlib import Path
import os

class ReentrancyDetector(AbstractDetector):
    ARGUMENT = 'check-reentrancy'
    HELP = 'Detect state variable writes after external calls (CEI violation)'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'https://github.com/your-repo/wiki/level8'
    WIKI_TITLE = 'Reentrancy Vulnerability (CEI Violation)'
    WIKI_DESCRIPTION = 'This detector identifies functions that write to state variables after performing an external call, violating the Check-Effects-Interactions pattern.'
    WIKI_EXPLOIT_SCENARIO = 'A user withdraws funds. The contract calls the user first, then updates their balance. The user uses a fallback function to call withdraw again before the balance is zeroed out.'
    WIKI_RECOMMENDATION = 'Always update state variables before making external calls.'

    def _detect(self):
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                # 1. Find the first external call node
                call_nodes = [n for n in func.nodes if any(isinstance(ir, (LowLevelCall, HighLevelCall)) for ir in n.irs)]
                
                if not call_nodes:
                    continue

                # We take the first call as the "Interaction" point
                first_call_node = min(call_nodes, key=lambda x: x.node_id)

                # 2. Look for any state variable writes that happen AFTER this node
                # We check all nodes with a higher node_id
                for node in func.nodes:
                    if node.node_id > first_call_node.node_id:
                        # 3. Check if this node writes to state
                        if len(node.state_variables_written) > 0:
                            written_vars = [v.name for v in node.state_variables_written]
                            info = [
                                f"Reentrancy Risk: {func.name} in {contract.name} writes to {written_vars} after a call!\n",
                                first_call_node,
                                " <- External call happens here\n",
                                node,
                                " <- Dangerous state write happens here\n"
                            ]
                            res = self.generate_result(info) # type: ignore
                            results.append(res)
                            # Once we find one violation in a function, we can move to the next function
                            break
        return results

if __name__ == "__main__":
    from slither import Slither
    current_dir = Path(__file__).resolve().parent
    vulnerable_sol = os.path.join(current_dir, "Vulnerable.sol")
    
    if os.path.exists(vulnerable_sol):
        print(f"🔍 Scanning for CEI Violations in: {vulnerable_sol}")
        slither = Slither(vulnerable_sol)
        slither.register_detector(ReentrancyDetector)
        results = slither.run_detectors()
        
        found = False
        for detector_results in results:
            for res in detector_results:
                print(f"[!] BUG: {res['description']}")
                found = True
        
        if not found:
            print("✅ All functions follow Check-Effects-Interactions.")