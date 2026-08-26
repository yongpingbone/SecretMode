package com.yongpingbone.secretmode.verification

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter

object FinalVerificationQrRenderer {
    fun render(payload: String, sizePx: Int): Bitmap {
        require(payload.isNotBlank()) { "QR payload must not be blank" }
        require(sizePx in 128..2048) { "QR bitmap size must be between 128 and 2048 px" }

        val matrix = QRCodeWriter().encode(
            payload,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx,
            mapOf(
                EncodeHintType.MARGIN to 1,
                EncodeHintType.CHARACTER_SET to "UTF-8",
            ),
        )
        val pixels = IntArray(sizePx * sizePx)
        for (y in 0 until sizePx) {
            for (x in 0 until sizePx) {
                pixels[y * sizePx + x] = if (matrix[x, y]) Color.BLACK else Color.WHITE
            }
        }
        return Bitmap.createBitmap(pixels, sizePx, sizePx, Bitmap.Config.ARGB_8888)
    }
}
