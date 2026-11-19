/* floating point: float, double, long double (x87), libm */
#include <stdio.h>
#include <math.h>
int main(void) {
    double s = 0; float f = 0; long double ld = 1;
    for (int i = 1; i <= 1000; i++) { s += 1.0 / (i * (double)i); f += 1.0f / i; ld *= 1.0001L; }
    printf("basel=%.15f pi^2/6=%.15f\n", s, M_PI * M_PI / 6);
    printf("harmonic(float)=%.7f  ld=%.18Lf\n", f, ld);
    printf("sqrt2=%.17g exp1=%.17g log10=%.17g\n", sqrt(2.0), exp(1.0), log(10.0));
    printf("sin=%.12f cos=%.12f atan2=%.12f pow=%.12f\n", sin(1.0), cos(1.0), atan2(1.0, -1.0), pow(2.5, 3.3));
    printf("floor=%g ceil=%g round=%g trunc=%d fmod=%g\n", floor(-2.5), ceil(-2.5), round(2.5), (int)-7.9, fmod(10.5, 3));
    printf("tiny=%e huge=%e nan=%f inf=%f\n", 1e-300 * 1e-10, 1e300 * 10, NAN, INFINITY);
    double v[5] = {3.5, -1.25, 1e10, 7.0/3, -0.0};
    for (int i = 0; i < 5; i++) printf("%a %.3f %lld\n", v[i], v[i], (long long)v[i]);
    return 0;
}
