export class CanaryFilter {
  constructor() {
    this.token = "[VALID_DATA_EOF_TOKEN]";
  }
  inject(data) { return `${data} ${this.token}`; }
  isTampered(incomingPayload) { return !incomingPayload.includes(this.token); }
}
