export type Checkout = { id: string; amountMinor: number; currency: string; merchantId: string };
export interface PaymentConnector {
  readonly provider: string;
  capabilities(): Promise<{ remoteNfc: boolean; live: boolean }>;
  createSession(checkout: Checkout): Promise<{ sessionId: string }>;
}
export class StripeConnector implements PaymentConnector {
  readonly provider = "stripe";
  async capabilities() { return { remoteNfc: false, live: false }; }
  async createSession(_checkout: Checkout): Promise<{ sessionId: string }> {
    throw new Error("Remote consumer NFC payments require provider approval; disabled.");
  }
}
