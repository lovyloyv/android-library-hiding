package dev.remap.testapp;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    static {
        System.loadLibrary("injector");
        System.loadLibrary("defend");
    }

    private static native String firstLabel();
    private static native String secondLabel();

    private TextView first;
    private TextView second;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER_VERTICAL);
        layout.setBackgroundColor(Color.rgb(245, 247, 250));
        int padding = Math.round(24 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(padding + insets.getSystemWindowInsetLeft(),
                    padding + insets.getSystemWindowInsetTop(),
                    padding + insets.getSystemWindowInsetRight(),
                    padding + insets.getSystemWindowInsetBottom());
            return insets;
        });

        first = addLabel(layout, padding);
        second = addLabel(layout, padding);
        setContentView(layout);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshLabels();
    }

    private TextView addLabel(LinearLayout layout, int padding) {
        TextView label = new TextView(this);
        label.setTextSize(22);
        label.setTextColor(Color.rgb(24, 40, 62));
        label.setPadding(0, padding, 0, padding);
        label.setGravity(Gravity.CENTER);
        label.setOnClickListener(view -> refreshLabels());
        layout.addView(label, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        return label;
    }

    private void refreshLabels() {
        first.setText(firstLabel());
        second.setText(secondLabel());
    }
}
