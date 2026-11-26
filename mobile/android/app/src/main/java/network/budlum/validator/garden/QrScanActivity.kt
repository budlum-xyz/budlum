package network.budlum.validator.garden

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.FrameLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.EnumMap
import java.util.concurrent.Executors

/**
 * The camera half of section 2.6.
 *
 * It reads a QR and hands the text back. It does not decide whether the
 * text is an invite: the core does that, and a scanner that judged
 * invites would be a second copy of the rules.
 *
 * It used to show the camera and never read anything. Two reasons, both
 * of them in the frame handling. A camera plane is padded - `rowStride`
 * is usually wider than the image - and the old code handed zxing the
 * image width as the row width, so every row after the first was read
 * from the wrong offset and the picture zxing saw was sheared. And the
 * frames arrive in the sensor's orientation, not the phone's, so a code
 * held upright in a portrait app arrives on its side. Both are handled
 * here, and the reader is told it may work harder on a blurry frame.
 */
class QrScanActivity : ComponentActivity() {

    private val executor = Executors.newSingleThreadExecutor()
    private var answered = false
    private var preview: PreviewView? = null

    private val reader = QRCodeReader()
    private val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
        // A phone in a hand is never quite still and a 413 byte record is a
        // dense code. Trying harder costs milliseconds on a frame that was
        // going to be thrown away anyway.
        put(DecodeHintType.TRY_HARDER, true)
        put(DecodeHintType.CHARACTER_SET, "UTF-8")
    }

    private val askCamera = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            start()
        } else {
            Toast.makeText(
                this,
                "Without the camera you can still paste the invite on the Join screen.",
                Toast.LENGTH_LONG,
            ).show()
            cancel()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val frame = FrameLayout(this)
        val view = PreviewView(this)
        frame.addView(
            view,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ),
        )
        frame.addView(hint())
        frame.addView(backButton())
        setContentView(frame)
        preview = view
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            start()
        } else {
            askCamera.launch(Manifest.permission.CAMERA)
        }
    }

    /** Say what the camera is for, so the view is not a bare picture. */
    private fun hint(): TextView = TextView(this).apply {
        text = context.getString(network.budlum.validator.R.string.g_point_at_qr)
        setTextColor(Color.WHITE)
        setBackgroundColor(Color.argb(140, 0, 0, 0))
        setPadding(32, 24, 32, 24)
        layoutParams = FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.TOP,
        )
    }

    /**
     * A way out that does not depend on knowing the gesture.
     *
     * Leaving this screen used to mean finding the system back gesture and
     * hoping. A camera that is pointed at nothing should always have a
     * door next to it.
     */
    private fun backButton(): Button = Button(this).apply {
        text = context.getString(network.budlum.validator.R.string.g_cancel)
        setOnClickListener { cancel() }
        layoutParams = FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL,
        ).apply { bottomMargin = 64 }
    }

    private fun cancel() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    private fun start() {
        val surface = preview ?: return
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = runCatching { future.get() }.getOrNull() ?: return@addListener
            val view = androidx.camera.core.Preview.Builder().build()
            view.surfaceProvider = surface.surfaceProvider
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                .build()
            analysis.setAnalyzer(executor) { image -> read(image) }
            runCatching {
                provider.unbindAll()
                provider.bindToLifecycle(
                    this,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    view,
                    analysis,
                )
            }.onFailure {
                Toast.makeText(this, "The camera would not open: " + it.message, Toast.LENGTH_LONG)
                    .show()
                cancel()
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun read(image: ImageProxy) {
        if (answered) {
            image.close()
            return
        }
        val text = runCatching { decode(image) }.getOrNull()
        image.close()
        if (!text.isNullOrBlank()) {
            answered = true
            runOnUiThread {
                setResult(Activity.RESULT_OK, Intent().putExtra(RESULT_TEXT, text))
                finish()
            }
        }
    }

    /**
     * One frame, tried the way it arrived and then turned.
     *
     * The Y plane alone is the luminance zxing wants, but it is padded to
     * `rowStride`, so that - not the image width - is the width of the
     * buffer. The crop is then the real image inside it.
     */
    private fun decode(image: ImageProxy): String? {
        val plane = image.planes.firstOrNull() ?: return null
        val buffer = plane.buffer
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)
        val stride = plane.rowStride.takeIf { it >= image.width } ?: image.width
        val rows = bytes.size / stride
        val height = minOf(image.height, rows)
        if (height <= 0) return null
        var source: LuminanceSource = PlanarYUVLuminanceSource(
            bytes,
            stride,
            height,
            0,
            0,
            image.width,
            height,
            false,
        )
        // Four turns covers every way the sensor can be mounted against
        // the way the phone is being held.
        repeat(4) {
            reader.reset()
            val text = runCatching {
                reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
            }.getOrNull()
            if (text != null) return text
            source = source.rotateCounterClockwise()
        }
        return null
    }

    override fun onDestroy() {
        super.onDestroy()
        executor.shutdown()
    }

    companion object {
        /** The extra the scanned text comes back in. */
        const val RESULT_TEXT = "garden.scanned.record"
    }
}
