export interface TurnkeyErrorBody {
  code: number;
  message: string;
  details: unknown[];
  turnkeyErrorCode: string;
}

export type TurnkeyHttpStatus = 400 | 401 | 403 | 404 | 429 | 500;

// HTTP status → gRPC status code (Turnkey's `code` field; observed `3` for 400).
const GRPC_CODE: Record<TurnkeyHttpStatus, number> = {
  400: 3, // INVALID_ARGUMENT
  401: 16, // UNAUTHENTICATED
  403: 7, // PERMISSION_DENIED
  404: 5, // NOT_FOUND
  429: 8, // RESOURCE_EXHAUSTED
  500: 2, // UNKNOWN
};

/** A boundary error that serializes to Turnkey's HTTP error envelope. */
export class TurnkeyError extends Error {
  readonly httpStatus: TurnkeyHttpStatus;
  readonly body: TurnkeyErrorBody;
  constructor(httpStatus: TurnkeyHttpStatus, message: string, details: unknown[] = []) {
    super(message);
    this.httpStatus = httpStatus;
    this.body = { code: GRPC_CODE[httpStatus], message, details, turnkeyErrorCode: "" };
  }
}
