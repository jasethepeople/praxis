export class IntegrityError extends Error {
  constructor() {
    super("Signed data failed integrity verification");
    this.name = "IntegrityError";
  }
}
