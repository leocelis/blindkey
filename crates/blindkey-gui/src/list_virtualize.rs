//! Entry-list viewport slicing (UC-20 / C43) — bound egui layout cost for large vaults.

/// Switch to viewport-only layout above this many filtered rows (UC-20 §3.3).
pub const LIST_VIRTUALIZE_THRESHOLD: usize = 100;
/// Estimated row height for scroll math (egui Body + padding).
pub const ENTRY_ROW_HEIGHT: f32 = 24.0;
/// Extra rows painted above/below the viewport to reduce pop-in while scrolling.
pub const VIRTUALIZE_MARGIN: usize = 3;

/// Visible index range for a scrolled list. Returns `0..item_count` when below the threshold.
pub fn visible_slice_range(
    item_count: usize,
    scroll_offset_y: f32,
    viewport_height: f32,
) -> std::ops::Range<usize> {
    if item_count <= LIST_VIRTUALIZE_THRESHOLD {
        return 0..item_count;
    }
    let first = (scroll_offset_y / ENTRY_ROW_HEIGHT).floor() as usize;
    let visible = (viewport_height / ENTRY_ROW_HEIGHT).ceil() as usize;
    let lo = first.saturating_sub(VIRTUALIZE_MARGIN);
    let hi = (first + visible + VIRTUALIZE_MARGIN * 2).min(item_count);
    lo..hi
}

/// Rows laid out this frame (test helper).
#[cfg(test)]
pub fn rows_painted_this_frame(
    item_count: usize,
    scroll_offset_y: f32,
    viewport_height: f32,
) -> usize {
    visible_slice_range(item_count, scroll_offset_y, viewport_height).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_lists_paint_every_row() {
        assert_eq!(visible_slice_range(100, 0.0, 400.0), 0..100);
        assert_eq!(rows_painted_this_frame(100, 0.0, 400.0), 100);
    }

    #[test]
    fn large_lists_bound_painted_rows() {
        let n = 600;
        let painted = rows_painted_this_frame(n, 0.0, 400.0);
        assert!(
            painted <= LIST_VIRTUALIZE_THRESHOLD / 10 + VIRTUALIZE_MARGIN * 2 + 20,
            "painted {painted} rows — expected bounded viewport slice"
        );
        assert!(painted < n);
    }

    #[test]
    fn scroll_mid_list_still_bounded() {
        let n = 600;
        let painted = rows_painted_this_frame(n, 2400.0, 400.0);
        assert!(painted < 40, "painted {painted}");
        assert!(painted < n);
    }
}
