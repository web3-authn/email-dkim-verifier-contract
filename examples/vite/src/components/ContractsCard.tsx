type ContractsCardProps = {
  webAuthnContractId: string;
  emailRecovererContractId: string;
  dkimVerifierContractId: string;
};

export function ContractsCard({
  webAuthnContractId,
  emailRecovererContractId,
  dkimVerifierContractId,
}: ContractsCardProps) {
  return (
    <div className="card">
      <h3>Contracts</h3>
      <dl>
        <div>
          <dt>WebAuthn</dt>
          <dd>{webAuthnContractId}</dd>
        </div>
        <div>
          <dt>EmailRecoverer</dt>
          <dd>{emailRecovererContractId}</dd>
        </div>
        <div>
          <dt>DKIM Verifier</dt>
          <dd>{dkimVerifierContractId}</dd>
        </div>
      </dl>
    </div>
  );
}
