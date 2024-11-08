/* eslint-disable no-console */

import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { corsOptions } from '~/config/corsOptions'
import { APIs_V1 } from '~/routes/v1/'

const START_SERVER = () => {
  // Init Express App
  const app = express()

  // Fix Cache from disk from ExpressJS
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store')
    next()
  })

  // Use Cookie
  app.use(cookieParser())

  // Allow CORS
  app.use(cors(corsOptions))

  // Enable req.body json data
  app.use(express.json())

  // Use Route APIs V1
  app.use('/v1', APIs_V1)

  // Should be store to env in the actual product
  const LOCAL_DEV_APP_PORT = 8017
  const LOCAL_DEV_APP_HOST = 'localhost'

  app.listen(LOCAL_DEV_APP_PORT, LOCAL_DEV_APP_HOST, () => {
    console.log(`Back-end Server is running at http://${LOCAL_DEV_APP_HOST}:${LOCAL_DEV_APP_PORT}`)
  })
}

(async () => {
  try {
    // Start Back-end Server
    console.log('Starting Server...')
    START_SERVER()
  } catch (error) {
    console.error(error)
    process.exit(0)
  }
})()
