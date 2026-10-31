// Background Gradient from the public Aceternity UI registry
// https://ui.aceternity.com/registry/background-gradient.json
// Author: Manu Arora <hi@manuarora.in>
// Used here as part of this site, with the palette slowed and limited to A3P colors.
// The paid Aceternity Pro licence is not used.

import { cn } from "../../lib/utils"
import { type ReactNode } from "react"
import { motion } from "motion/react"

const wash =
  "bg-[radial-gradient(circle_farthest-side_at_0_100%,#1c4e6e,transparent),radial-gradient(circle_farthest-side_at_100%_0,#8a3d2f,transparent),radial-gradient(circle_farthest-side_at_100%_100%,#1d6b45,transparent),radial-gradient(circle_farthest-side_at_0_0,#c5dbe6,#fbfbfc)]"

export const BackgroundGradient = ({
  children,
  className,
  containerClassName,
  animate = true,
}: {
  children?: ReactNode
  className?: string
  containerClassName?: string
  animate?: boolean
}) => {
  const variants = {
    initial: {
      backgroundPosition: "0 50%",
    },
    animate: {
      backgroundPosition: ["0, 50%", "100% 50%", "0 50%"],
    },
  }
  return (
    <div className={cn("group relative p-[3px]", containerClassName)}>
      <motion.div
        variants={animate ? variants : undefined}
        initial={animate ? "initial" : undefined}
        animate={animate ? "animate" : undefined}
        transition={
          animate
            ? {
                duration: 14,
                repeat: Infinity,
                repeatType: "reverse",
              }
            : undefined
        }
        style={{
          backgroundSize: animate ? "400% 400%" : undefined,
        }}
        className={cn(
          "absolute inset-0 z-[1] rounded-3xl opacity-30 blur-lg transition duration-500 will-change-transform group-hover:opacity-45",
          wash,
        )}
      />
      <motion.div
        variants={animate ? variants : undefined}
        initial={animate ? "initial" : undefined}
        animate={animate ? "animate" : undefined}
        transition={
          animate
            ? {
                duration: 14,
                repeat: Infinity,
                repeatType: "reverse",
              }
            : undefined
        }
        style={{
          backgroundSize: animate ? "400% 400%" : undefined,
        }}
        className={cn(
          "absolute inset-0 z-[1] rounded-3xl opacity-70 will-change-transform",
          wash,
        )}
      />

      <div className={cn("relative z-10", className)}>{children}</div>
    </div>
  )
}
