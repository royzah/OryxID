import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { Button } from "./ui/button";
import { toast } from "./ui/use-toast";

interface CopyToClipboardProps {
  text: string;
  label?: string;
  className?: string;
  variant?: "default" | "ghost" | "outline";
  size?: "default" | "sm" | "lg" | "icon";
}

export function CopyToClipboard({
  text,
  label,
  className,
  variant = "ghost",
  size = "sm",
}: CopyToClipboardProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast({
        title: "Copied!",
        description: `${label || "Text"} copied to clipboard`,
      });
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({
        title: "Failed to copy",
        description: "Could not copy to clipboard",
        variant: "destructive",
      });
    }
  };

  return (
    <Button
      variant={variant}
      size={size}
      onClick={handleCopy}
      className={className}
    >
      {copied ? (
        <Check className="h-4 w-4 text-green-500" />
      ) : (
        <Copy className="h-4 w-4" />
      )}
      {label && <span className="ml-2">{label}</span>}
    </Button>
  );
}
