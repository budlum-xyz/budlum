package network.budlum.validator.garden

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
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
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors

/**
 * The camera half of section 2.6.
 *
 * It reads a QR and hands the text back. It does not decide whether the
 * text is an invite: the core does that, and a scanner that judged invites
 * would be a second copy of the rules.
 *
 * Section 4.4 of the directive expects a refused permission to be a plain
 * refusal rather than a crash, so a phone without camera permission simply
 * says so and returns.
 */
class QrScanActivity : ComponentActivity() {

    private val executor = Executors.newSingleThreadExecutor()
    private var answered = false

    private val askCamera = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            start()
        } else {
            Toast.makeText(this, "The camera is needed to scan a QR.", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val view = PreviewView(this)
        setContentView(view)
        this.preview = view
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            start()
        } else {
            askCamera.launch(Manifest.permission.CAMERA)
        }
    }

    private var preview: PreviewView? = null

    private fun start() {
        val surface = preview ?: return
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val preview = androidx.camera.core.Preview.Builder().build()
            preview.surfaceProvider = surface.surfaceProvider
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(executor) { image -> read(image) }
            provider.unbindAll()
            provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, ContextCompat.getMainExecutor(this))
    }

    private fun read(image: ImageProxy) {
        if (answered) {
            image.close()
            return
        }
        val plane = image.planes.firstOrNull()
        if (plane == null) {
            image.close()
            return
        }
        val bytes = ByteArray(plane.buffer.remaining())
        plane.buffer.get(bytes)
        val source = PlanarYUVLuminanceSource(
            bytes,
            image.width,
            image.height,
            0,
            0,
            image.width,
            image.height,
            false,
        )
        val text = runCatching {
            QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source))).text
        }.getOrNull()
        image.close()
        if (!text.isNullOrBlank()) {
            answered = true
            runOnUiThread {
                setResult(Activity.RESULT_OK, Intent().putExtra(RESULT_TEXT, text))
                finish()
            }
        }
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
