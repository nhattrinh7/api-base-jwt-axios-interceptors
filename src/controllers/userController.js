// Author: TrungQuanDev: https://youtube.com/@trungquandev
import { StatusCodes } from 'http-status-codes'
import ms from 'ms'
import {
  JwtProvider,
  ACCESS_TOKEN_SECRET_SIGNATURE,
  REFRESH_TOKEN_SECRET_SIGNATURE
} from '~/providers/JwtProvider'

/**
 * Mock nhanh thông tin user thay vì phải tạo Database rồi query.
 * Nếu muốn học kỹ và chuẩn chỉnh đầy đủ hơn thì xem Playlist này nhé:
 * https://www.youtube.com/playlist?list=PLP6tw4Zpj-RIMgUPYxhLBVCpaBs94D73V
 */
const MOCK_DATABASE = {
  USER: {
    ID: 'trungquandev-sample-id-12345678',
    EMAIL: 'trungquandev.official@gmail.com',
    PASSWORD: 'trungquandev@123'
  }
}


const login = async (req, res) => {
  try {
    console.log('req.body', req.body)
    if (req.body.email !== MOCK_DATABASE.USER.EMAIL || req.body.password !== MOCK_DATABASE.USER.PASSWORD) {
      res.status(StatusCodes.FORBIDDEN).json({ message: 'Your email or password is incorrect!' })
      return
    }

    // Trường hợp nhập đúng thông tin tài khoản, tạo token và trả về cho phía Client
    // Tạo thông tin payload để đính kèm trong Token: gồm id và email của user
    const userInfo = {
      id: MOCK_DATABASE.USER.ID,
      email: MOCK_DATABASE.USER.EMAIL
    }

    // Tạo ra 2 loại token là Access token và Refresh token để trả về FE
    const accessToken = await JwtProvider.generateToken(
      userInfo, ACCESS_TOKEN_SECRET_SIGNATURE, '1h'
    )

    const refreshToken = await JwtProvider.generateToken(
      userInfo, REFRESH_TOKEN_SECRET_SIGNATURE, '2h'
    )

    /**
     * Xử lí trường hợp trả về http only cookie cho phía trình duyệt
     * maxAge: thời gian tồn tại của cookie tính bằng giây, hết thời gian sẽ bị xóa
     * Lưu ý: thời gian sống của cookie khác với thời gian sống của token
     */
    res.cookie('accessToken', accessToken, { httpOnly: true, secure: true, sameSite: 'none', maxAge:  ms('14 days') })
    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'none', maxAge:  ms('14 days') })

    // THỰC TẾ THÌ DÙNG COOKIE RỒI THÌ THÔI HOẶC DÙNG LOCALSTORAGE RỒI THÌ THÔI COOKIE, CHẢ QUA DÙNG THỬ CẢ 2 CHO BIẾT
    // Trả về thông tin user và các token cho FE cần lưu vào Localstorage
    res.status(StatusCodes.OK).json({
      ...userInfo,
      // accessToken,
      // refreshToken
    })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}


const logout = async (req, res) => {
  try {
    // Xóa Cookie - đơn giản là làm ngược lại so với gán cookie ở login
    res.clearCookie('accessToken')
    res.clearCookie('refreshToken')

    res.status(StatusCodes.OK).json({ message: 'Logout API success!' })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const refreshToken = async (req, res) => {
  try {
    // Cách 1: Lấy refreshToken luôn từ Cookie đã đính kèm vào request
    const refreshTokenFromCookie = req.cookies?.refreshToken

    // Cách 2: Từ Local Storage phía FE sẽ truyền vào body khi gọi API
    const refreshTokenFromBody = req.body?.refreshToken

    // Verify xem token có hợp lệ không
    const refreshTokenDecoded = await JwtProvider.verifyToken(
      // refreshTokenFromCookie,
      refreshTokenFromBody,
      REFRESH_TOKEN_SECRET_SIGNATURE
    )
    // Hợp lệ thì xử lí tiếp phía dưới

    // trong refreshTokenDecoded có userInfo rồi do lúc tạo access và refresh Token có nhét userInfo vào,
    // vì vậy có thể lấy luôn userInfo từ refreshTokenDecoded ra, tiết kiệm query vào DB để lấy data mới
    const userInfo = {
      id: refreshTokenDecoded.id,
      email: refreshTokenDecoded.email
    }

    // Tạo accessToken mới
    const accessToken = await JwtProvider.generateToken(
      userInfo, ACCESS_TOKEN_SECRET_SIGNATURE, 5
    )

    // Res lại cookie accessToken mới cho trường hợp sử dụng cookie
    res.cookie('accessToken', accessToken, { httpOnly: true, secure: true, sameSite: 'none', maxAge:  ms('14 days') })

    // Trả về accessToken cho trường hợp FE cần update lại trong Local Storage
    res.status(StatusCodes.OK).json({ accessToken })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Refresh Token API failed!' })
  }
}

export const userController = {
  login,
  logout,
  refreshToken
}
