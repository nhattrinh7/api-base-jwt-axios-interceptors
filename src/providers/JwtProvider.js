import JWT from 'jsonwebtoken'


/**
 * Function tạo mới 1 token cần 3 than số đầu vào
 * userInfo: những thông tin muốn đính kèo vào token
 * secretSignature: chữ kí bí mật dạng 1 chuỗi string ngẫu nhiên, docs gọi là privateKey thì tùy
 * tokenLife: thời gian sống của token
 */

const generateToken = async (userInfo, secretSignature, tokenLife) => {
  try {
    //
    return JWT.sign(userInfo, secretSignature, { algorithm: 'HS256', expiresIn: tokenLife })
  } catch (error) { throw new Error(error) }
}


const verifyToken = async (token, secretSignature) => {
  try {
    //
    return JWT.verify(token, secretSignature)
  } catch (error) { throw new Error(error) }
}

/**
 * 2 cái chữ ký bí mật quan trọng trong dự án. Dành cho JWT - Jsonwebtokens
 * Lưu ý phải lưu vào biến môi trường ENV trong thực tế cho bảo mật.
 * Ở đây mình làm Demo thôi nên mới đặt biến const và giá trị random ngẫu nhiên trong code nhé.
 * Xem thêm về biến môi trường: https://youtu.be/Vgr3MWb7aOw
 */
export const ACCESS_TOKEN_SECRET_SIGNATURE = 'KBgJwUETt4HeVD05WaXXI9V3JnwCVP'
export const REFRESH_TOKEN_SECRET_SIGNATURE = 'fcCjhnpeopVn2Hg1jG75MUi62051yL'

export const JwtProvider = {
  generateToken,
  verifyToken
}