/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {

      let parsedUrl: URL

      try {
        parsedUrl = new URL(req.body.imageUrl)
      } catch {
        return next(new Error('Invalid URL'))
      }

      // --------------------------------------------
      // ✔ OWASP-Compliant Whitelist (based on example)
      // --------------------------------------------
      const allowedSchemes = ['http:', 'https:']
      const allowedDomains = ['trusted1.example.com', 'trusted2.example.com']

      if (
        !allowedSchemes.includes(parsedUrl.protocol) ||
        !allowedDomains.includes(parsedUrl.hostname)
      ) {
        return next(new Error('URL not allowed'))
      }

      // Safe URL
      const safeUrl = parsedUrl.toString()

      // --------------------------------------------
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }

      try {
        const response = await fetch(safeUrl)

        if (!response.ok || !response.body) {
          throw new Error('URL returned non-OK status or empty body')
        }

        // Determine file extension safely
        const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif']
          .includes(parsedUrl.pathname.split('.').pop()?.toLowerCase() || '')
          ? parsedUrl.pathname.split('.').pop()!.toLowerCase()
          : 'jpg'

        const outputPath =
          `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`

        const fileStream = fs.createWriteStream(outputPath, { flags: 'w' })
        await finished(Readable.fromWeb(response.body as any).pipe(fileStream))

        const user = await UserModel.findByPk(loggedInUser.data.id)
        await user?.update({
          profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
        })

      } catch (error) {
        try {
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: safeUrl })
          logger.warn(
            `Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`
          )
        } catch (error) {
          next(error)
          return
        }
      }
    }

    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
