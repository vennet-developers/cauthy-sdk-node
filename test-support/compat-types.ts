// @cauthyhq/node 1.0 takes every configuration cauthy-auth 0.42 took: an
// application's options compile unchanged. `npm run typecheck` checks this file.
import type { ContractOptions as TheirContract, CauthyOptions as TheirOptions, SystemOptions as TheirSystem } from 'cauthy-auth'
import type { McpAuthOptions as TheirMcp } from 'cauthy-auth/mcp'
import type { ContractOptions as OurContract } from '../src/contract'
import type { McpAuthOptions as OurMcp } from '../src/mcp'
import type { SystemOptions as OurSystem } from '../src/system'
import type { CauthyOptions as OurOptions } from '../src/types'

export const options = (o: TheirOptions): OurOptions => o
export const system = (o: TheirSystem): OurSystem => o
export const contract = (o: TheirContract): OurContract => o
export const mcp = (o: TheirMcp): OurMcp => o
