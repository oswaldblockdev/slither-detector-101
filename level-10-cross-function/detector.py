from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import SolidityCall, Binary
from pathlib import Path
import os

class ProxyInitializationDetector(AbstractDetector):
    ARGUMENT = 'check-init'
    HELP = 'Detect uninitialized implementation/proxy vulnerabilities'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'https://github.com/your-repo/wiki/level10'
    WIKI_TITLE = 'Uninitialized Implementation'
    WIKI_DESCRIPTION = 'Sensitive initialization functions should be protected by a global boolean to prevent re-initialization by attackers.'
    WIKI_EXPLOIT_SCENARIO = 'An attacker calls the setup() function on a logic contract that was never initialized, becoming the admin and potentially destroying the contract via selfdestruct.'
    WIKI_RECOMMENDATION = 'Use an "initializer" modifier or a require(!initialized) check at the start of setup functions.'

    def _detect(self):
        results = []
        for contract in self.contracts:
            # 1. Identify the 'initialized' state variable
            init_var = next((v for v in contract.state_variables if 'init' in v.name.lower()), None) # type: ignore
            
            if not init_var:
                continue

            # 2. Look for functions that look like setup/initialization functions
            for func in contract.functions:
                if any(name in func.name.lower() for name in ["init", "setup", "configure"]):
                    
                    # 3. Check if this function reads the 'initialized' variable in a guard
                    # We check if any node performs a comparison or require using init_var
                    is_protected = False
                    for node in func.nodes:
                        # Check if the variable is read in this node
                        if init_var in node.state_variables_read:
                            # Check if it's used in a SolidityCall (require) or an IF node
                            for ir in node.irs:
                                if isinstance(ir, (SolidityCall, Binary)):
                                    is_protected = True
                                    break
                        if is_protected:
                            break

                    if not is_protected:
                        info = [
                            f"Critical: {func.name} in {contract.name} is a sensitive setup function but does not check the '{init_var.name}' guard!\n",
                            func # Attach the whole function for context
                        ]
                        res = self.generate_result(info) # type: ignore
                        results.append(res)
        return results

if __name__ == "__main__":
    from slither import Slither
    current_dir = Path(__file__).resolve().parent
    vulnerable_sol = os.path.join(current_dir, "Vulnerable.sol")
    
    if os.path.exists(vulnerable_sol):
        print(f"🏰 Analyzing Global State Flow in: {vulnerable_sol}")
        slither = Slither(vulnerable_sol)
        slither.register_detector(ProxyInitializationDetector)
        results = slither.run_detectors()
        
        found = False
        for detector_results in results:
            for res in detector_results:
                print(f"[!] BUG: {res['description']}")
                found = True
        
        if not found:
            print("✅ Initialization guards appear correct.")