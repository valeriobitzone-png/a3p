// Number Ticker from Magic UI <https://magicui.design/docs/components/number-ticker>
// MIT License. Copyright Magic UI.
// The count-up was removed. The finished number is plain text so it is visible
// with no animation, including in WebKit and when JavaScript is off after prerender.

import type { ComponentPropsWithoutRef } from "react"

import { cn } from "../../lib/utils"

interface NumberTickerProps extends ComponentPropsWithoutRef<"span"> {
  value: number
  decimalPlaces?: number
}

function formatNumber(value: number, decimalPlaces: number) {
  return Intl.NumberFormat("en-US", {
    minimumFractionDigits: decimalPlaces,
    maximumFractionDigits: decimalPlaces,
  }).format(value)
}

export function NumberTicker({
  value,
  className,
  decimalPlaces = 0,
  ...props
}: NumberTickerProps) {
  return (
    <span className={cn("inline-block tabular-nums text-base-content", className)} {...props}>
      {formatNumber(value, decimalPlaces)}
    </span>
  )
}
