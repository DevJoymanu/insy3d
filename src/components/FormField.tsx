import type { FieldError } from "react-hook-form";

export default function FormField(props: {
  label: string;
  children: React.ReactNode;
  error?: FieldError;
  hint?: string;
}) {
  return (
    <div className={`field ${props.error ? "error" : ""}`}>
      <label>{props.label}</label>
      {props.children}
      {props.hint && !props.error && (
        <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          {props.hint}
        </div>
      )}
      {props.error && (
        <div className="err" role="alert" style={{ marginTop: 6 }}>
          {props.error.message}
        </div>
      )}
    </div>
  );
}