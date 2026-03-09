from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
from pathlib import Path
import os

class GasExhaustionDetector(AbstractDetector):
    ARGUMENT = 'check-loops'
    HELP = 'Detect loops iterating over dynamic state arrays'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://github.com/your-repo/wiki/level3'
    WIKI_TITLE = 'Gas Exhaustion in Loops'
    WIKI_DESCRIPTION = 'This detector identifies loops that iterate over dynamic state variables, which can lead to Denial of Service (DoS) due to gas limits.'
    WIKI_EXPLOIT_SCENARIO = 'If a dynamic array grows too large, the gas cost to iterate through it will exceed the block gas limit, making the function uncallable.'
    WIKI_RECOMMENDATION = 'Avoid unbounded loops over dynamic state variables. Consider using a pattern where users pull their own data or process the array in batches.'

    def _detect(self):
        # detect conditions:
        # 1. iterate through nodes to find loops
        # 2. check variables read in loop header
        # 3. flag if reading a dynamic state array
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                for node in func.nodes:
                    # 1. Identify loop entry nodes
                    if node.type == NodeType.IFLOOP:
                        # 2. Analyze state variables read in the loop condition
                        for var in node.state_variables_read:
                            # 3. Check if variable is a dynamic array (e.g., uint[] or address[])
                            if hasattr(var.type, 'is_dynamic_array') and var.type.is_dynamic_array: # type: ignore
                                print(type(var.type))
                                info = [f"Gas Warning: {func.name} in {contract.name} iterates over dynamic array '{var.name}'!\n"]
                                res = self.generate_result(info) # type: ignore
                                results.append(res)
        return results

if __name__ == "__main__":
    from slither import Slither
    # Path handling relative to this script
    current_dir = Path(__file__).resolve().parent
    vulnerable_sol = os.path.join(current_dir, "Vulnerable.sol")
    
    if not os.path.exists(vulnerable_sol):
        print(f"❌ Error: {vulnerable_sol} not found.")
    else:
        print(f"🔍 Analyzing: {vulnerable_sol}")
        slither = Slither(vulnerable_sol)
        slither.register_detector(GasExhaustionDetector)
        results = slither.run_detectors()
        
        found = False
        for detector_results in results:
            for res in detector_results:
                print(f"[!] BUG: {res['description']}")
                found = True
        
        if not found:
            print("✅ No unbounded loops detected.")