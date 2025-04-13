import { StatusCodes } from 'http-status-codes'
import {
  JwtProvider,
  ACCESS_TOKEN_SECRET_SIGNATURE
} from '~/providers/JwtProvider'

// Middleware này lấy và xác thực JWT accessToken nhận được từ FE có hợp lệ hay không

const isAuthorized = async (req, res, next) => {
  // Cách 1: lấy accessToken trong request cookie phía client - withCredentials và credentials
  const accessTokenFromCookie = req.cookies?.accessToken
  if (!accessTokenFromCookie) {
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Unauthorized - token not found' })
    return
  }

  // Cách 2: Lấy accessToken trong trường hợp FE lưu Local Storage và gửi lên qua header Authorization
  // const accessTokenFromHeader = req.headers.authorization
  // if (!accessTokenFromHeader) {
  //   res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Unauthorized - token not found' })
  //   return
  // }

  try {
    // Bước 1: Giải mã token xem nó có hợp lệ hay không
    const accessTokenDecoded = await JwtProvider.verifyToken(
      accessTokenFromCookie,
      // accessTokenFromHeader.substring('Bearer '.length),
      ACCESS_TOKEN_SECRET_SIGNATURE
    )

    // Bước 2: QUAN TRỌNG: Nếu token hợp lệ, cần lưu thông tin giải mã được vào req.jwtDecoded. để sử dụng cho các tầng cần xử lí phía sau
    req.jwtDecoded = accessTokenDecoded // theo như ảnh bảo thì chính là payload - check lại thử xem

    // Bước 3: Cho phép request đi tiếp
    next()
  } catch (error) {
    // console.log('Error from middleware', error)
    // Trường hợp lỗi 1: Nếu cái accessToken bị hết hạn, ta cần trả về 1 cái mã lỗi 410 - GONE cho FE để gọi API refreshToken
    if (error.message?.includes('jwt expired')) {
      res.status(StatusCodes.GONE).json({ message: 'Need to refesh Token' })
      return
    }
    // 401 - UNAUTHORIZED -  Truy cập trái phép
    // Trường hợp lỗi 2: Nếu accessToken không hợp lệ do bất kì điều gì khác, thẳng tay trả về mã 401 cho FE Logout hay gì thì tùy
    res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Please login!' })
  }
}

export const authMiddleware = {
  isAuthorized
}
